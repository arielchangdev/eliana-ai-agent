"""引擎接線層：六個既有子引擎的真實方法 ↔ 整合層 Port 介面 的翻譯。

整合層的 pipeline handlers 只認識 subsystems.py 定義的 Port（收發純 dict）。
但真實引擎用的是各自的領域模型（ScanOperation / ScanResult / TransactionRecord /
TaskResult…）。本模組提供 adapter 把兩邊接起來：pipeline dict ↔ 引擎領域模型。

安全設計：
- **AUTHORIZE 安全閘門（選項 A）**：`request_authorization` 只把請求送進
  Authorization_Gate（狀態 PENDING），然後 pipeline 停在此階段等人工核准，
  **不會**自動往 SCAN 前進。掃描永遠不會在未經人工核准下發生。
- **run_scan dry-run 開關**：預設 dry_run=True，只回報「將執行的掃描計畫」而
  不真的呼叫 Kali 工具。要真跑須在 VM 上明確以 dry_run=False 建構，且僅對
  已授權目標。

本模組延遲匯入各引擎模組（僅在 VM 上、引擎在 sys.path 時才 import），因此在
本機（引擎不一定可匯入）仍能匯入本檔並以 fake 引擎測試翻譯邏輯。
"""
from __future__ import annotations

from typing import Any

import structlog

from .subsystems import SubsystemNotWired

logger = structlog.get_logger(__name__)


class AuthorizationPending(Exception):
    """AUTHORIZE 階段：授權請求已送出，等待人工核准（安全閘門，停止 pipeline）。"""

    def __init__(self, operation_id: str, message: str = "") -> None:
        super().__init__(message or f"authorization pending for operation {operation_id}")
        self.operation_id = operation_id


# --------------------------------------------------------------------------- #
# BountyHunter Adapter（實作 subsystems.BountyHunterPort）
# --------------------------------------------------------------------------- #
class BountyHunterAdapter:
    """接 eliana-bounty-hunter 的 Crawler / AuthorizationGate / ScanEngine / ReportGenerator。

    參數（VM 啟動時注入真實物件；本機測試注入 fake）：
      crawler:    具 crawl_all_platforms() -> list[BountyProgram]
      auth_gate:  具 request_authorization(ScanOperation) -> AuthDecision
      scan_engine: 具 execute_scan(ScanTarget, ScanProfile) -> ScanResult
      report_gen: 具 generate_report(...) -> Report
      dry_run:    True 時 scan 不真的執行（只回報計畫）
    """

    def __init__(
        self,
        *,
        crawler: Any | None = None,
        auth_gate: Any | None = None,
        scan_engine: Any | None = None,
        report_gen: Any | None = None,
        dry_run: bool = True,
        auth_db_path: str | None = None,
        ssh_channel: Any | None = None,
    ) -> None:
        self._crawler = crawler
        self._auth_gate = auth_gate
        self._scan_engine = scan_engine
        self._report_gen = report_gen
        self.dry_run = dry_run
        self._auth_db_path = auth_db_path
        self._ssh_channel = ssh_channel
        self._ssh_connected = False

    # ----- SEARCH ----- #
    async def search_programs(self, criteria: dict) -> list[dict]:
        if self._crawler is None:
            raise SubsystemNotWired("bounty crawler not wired")
        programs = await self._crawler.crawl_all_platforms()
        # 領域模型 → dict（BountyProgram 有 to_dict）
        out = []
        for p in programs:
            out.append(p.to_dict() if hasattr(p, "to_dict") else dict(p))
        return out

    # ----- AUTHORIZE（安全閘門）----- #
    async def request_authorization(self, program: dict) -> bool:
        """安全授權閘門（選項 A）：先查 DB 已核准授權，有則放行；否則送 PENDING 並擋住。"""
        if self._auth_gate is None:
            raise SubsystemNotWired("authorization gate not wired")

        target_url = str(program.get("target_url") or _first_scope(program))

        if self._auth_db_path and self._has_approved_authorization(target_url):
            logger.info("authorization_approved_found", target=target_url)
            return True

        operation = self._build_scan_operation(program)
        decision = await self._auth_gate.request_authorization(operation)
        status = getattr(decision, "status", None)
        status_val = getattr(status, "value", status)
        logger.info("authorization_requested",
                    operation_id=getattr(operation, "id", None),
                    target=target_url, status=status_val)
        return str(status_val).lower() == "approved"

    def _has_approved_authorization(self, target_url: str) -> bool:
        import sqlite3
        try:
            conn = sqlite3.connect(self._auth_db_path)
            try:
                cur = conn.execute(
                    "SELECT COUNT(*) FROM authorizations "
                    "WHERE target_url = ? AND status = 'approved'",
                    (target_url,),
                )
                return cur.fetchone()[0] > 0
            finally:
                conn.close()
        except Exception as exc:
            logger.warning("auth_db_check_failed", error=str(exc))
            return False

    # ----- SCAN ----- #
    async def run_scan(self, target: dict) -> dict:
        """執行掃描。dry_run=True 時只回報將執行的計畫，不呼叫 Kali 工具。"""
        if self._scan_engine is None:
            raise SubsystemNotWired("scan engine not wired")

        scan_target, profile = self._build_target_and_profile(target)

        if self.dry_run:
            tools = [getattr(t, "value", str(t)) for t in getattr(profile, "tools", [])]
            logger.warning("scan_dry_run",
                           target=getattr(scan_target, "target_url", None),
                           tools=tools)
            return {
                "dry_run": True,
                "planned_target": getattr(scan_target, "target_url", None),
                "planned_tools": tools,
                "vulnerabilities": [],   # dry-run 不產生真實結果
            }

        await self._ensure_ssh_connected()
        result = await self._scan_engine.execute_scan(scan_target, profile)
        return self._scan_result_to_dict(result)

    async def _ensure_ssh_connected(self) -> None:
        if self._ssh_channel is None or self._ssh_connected:
            return
        try:
            connect = getattr(self._ssh_channel, "connect", None)
            if connect is not None:
                await connect()
            if self._scan_engine is not None:
                setattr(self._scan_engine, "_ssh", self._ssh_channel)
            self._ssh_connected = True
            logger.info("ssh_channel_connected_for_scan")
        except Exception as exc:
            logger.warning("ssh_connect_failed", error=str(exc))

    # ----- REPORT ----- #
    async def generate_report(self, scan_result: dict) -> dict:
        if self._report_gen is None:
            raise SubsystemNotWired("report generator not wired")
        vulns = scan_result.get("vulnerabilities") or []
        if not vulns:
            return {"reports": [], "note": "no vulnerabilities to report"}
        # 逐一產生報告（此處僅示接線；細節依 ReportGenerator.generate_report 簽名）
        reports = []
        for v in vulns:
            try:
                report = await self._report_gen.generate_report(v)
                reports.append(self._report_to_dict(report))
            except Exception as exc:  # noqa: BLE001
                logger.warning("report_generation_failed", error=str(exc))
        return {"reports": reports, "count": len(reports)}

    # ----- 領域模型建構（延遲匯入引擎）----- #
    def _build_scan_operation(self, program: dict):
        m = _import_bounty_models()
        target = m.ScanTarget(
            program_id=str(program.get("id", "")),
            target_url=_first_scope(program),
            target_type=m.TargetType.WEB_APP,
        )
        profile = m.ScanProfile(tools=[m.ScanTool.NUCLEI])
        return m.ScanOperation(
            target=target, profile=profile,
            program_id=str(program.get("id", "")),
        )

    def _build_target_and_profile(self, target: dict):
        m = _import_bounty_models()
        scan_target = m.ScanTarget(
            program_id=str(target.get("program_id", target.get("id", ""))),
            target_url=str(target.get("target_url") or _first_scope(target)),
            target_type=m.TargetType.WEB_APP,
        )
        profile = m.ScanProfile(tools=[m.ScanTool.NUCLEI])
        return scan_target, profile

    @staticmethod
    def _scan_result_to_dict(result: Any) -> dict:
        vulns = getattr(result, "vulnerabilities", []) or []
        return {
            "scan_id": getattr(result, "scan_id", ""),
            "status": getattr(getattr(result, "status", None), "value",
                              str(getattr(result, "status", ""))),
            "vulnerabilities": [
                {
                    "id": getattr(v, "id", ""),
                    "title": getattr(v, "title", ""),
                    "severity": getattr(getattr(v, "severity", None), "value",
                                        str(getattr(v, "severity", ""))),
                    "cve_id": getattr(v, "cve_id", None),
                    "affected_endpoint": getattr(v, "affected_endpoint", ""),
                }
                for v in vulns
            ],
        }

    @staticmethod
    def _report_to_dict(report: Any) -> dict:
        return {
            "id": getattr(report, "id", ""),
            "title": getattr(report, "title", ""),
            "vulnerability_id": getattr(report, "vulnerability_id", ""),
            "program_id": getattr(report, "program_id", ""),
            "severity": getattr(getattr(report, "cvss", None), "severity_label", ""),
        }


# --------------------------------------------------------------------------- #
# Wallet Adapter（實作 subsystems.WalletPort）
# --------------------------------------------------------------------------- #
class WalletAdapter:
    """接 eliana-digital-wallet 的 TransactionLedger.record_transaction。"""

    def __init__(self, *, ledger: Any | None = None) -> None:
        self._ledger = ledger
        self._initialized = False

    async def _ensure_initialized(self) -> None:
        if self._initialized or self._ledger is None:
            return
        init = getattr(self._ledger, "initialize", None)
        if init is not None:
            try:
                await init()
            except Exception as exc:
                logger.warning("ledger_init_failed", error=str(exc))
        self._initialized = True

    async def record_bounty(self, report: dict) -> dict:
        if self._ledger is None:
            raise SubsystemNotWired("transaction ledger not wired")
        await self._ensure_initialized()
        tx = self._build_transaction_record(report)
        txid = await self._ledger.record_transaction(tx)
        return {"txid": txid, "recorded": True}

    def _build_transaction_record(self, report: dict):
        m = _import_wallet_schemas()
        from datetime import datetime, timezone
        # report 可能含 reports list；取第一筆的資訊或用預設
        reports = report.get("reports") or []
        first = reports[0] if reports else {}
        return m.TransactionRecord(
            txid=str(report.get("txid", f"pending-{datetime.now(timezone.utc).timestamp()}")),
            amount_btc=float(report.get("amount_btc", 0.0)),
            amount_sat=int(report.get("amount_sat", 0)),
            address=str(report.get("address", "")),
            confirmed_at=datetime.now(timezone.utc),
            platform=str(report.get("platform", "")) or None,
            vuln_id=str(first.get("vulnerability_id", "")) or None,
            severity=(first.get("severity") or None),
            note=str(report.get("note", "")) or None,
        )


# --------------------------------------------------------------------------- #
# Learning Adapter（實作 subsystems.LearningPort）
# --------------------------------------------------------------------------- #
class LearningAdapter:
    """接 eliana-learning-engine 的 StrategyOptimizer.record_result。"""

    def __init__(self, *, optimizer: Any | None = None,
                 db_path: str | None = None) -> None:
        self._optimizer = optimizer
        self._db_path = db_path
        self._init_lock = None

    async def _ensure_optimizer(self):
        if self._optimizer is not None:
            return self._optimizer
        if self._db_path is None:
            return None
        import asyncio
        if self._init_lock is None:
            self._init_lock = asyncio.Lock()
        async with self._init_lock:
            if self._optimizer is None:
                try:
                    from src.db import SQLiteDB
                    from src.optimizer.strategy_optimizer import StrategyOptimizer
                    db = SQLiteDB(self._db_path)
                    await db.initialize()
                    self._optimizer = StrategyOptimizer(db)
                    logger.info("learning_optimizer_initialized", db_path=self._db_path)
                except Exception as exc:
                    logger.warning("learning_optimizer_init_failed", error=str(exc))
                    return None
        return self._optimizer

    async def record_result(self, feedback: dict) -> None:
        optimizer = await self._ensure_optimizer()
        if optimizer is None:
            logger.debug("learning optimizer not wired; skip feedback")
            return
        task_result = self._build_task_result(feedback)
        await optimizer.record_result(task_result)

    def _build_task_result(self, feedback: dict):
        import uuid

        outcome = "success" if feedback.get("success") else "failure"
        task_id = str(feedback.get("pipeline_id") or uuid.uuid4())
        strategy_id = str(feedback.get("strategy_id", "default"))
        target_type = str(feedback.get("target_type", "web_app"))
        details = (f"vuln_found={bool(feedback.get('vuln_found', False))}; "
                   f"failed_stage={feedback.get('failed_stage')}")
        payload = {
            "task_id": task_id,
            "strategy_id": strategy_id,
            "target_type": target_type,
            "outcome": outcome,
            "details": details,
        }
        try:
            m = _import_learning_models()
        except Exception:  # noqa: BLE001
            return payload
        try:
            return m.TaskResult(
                task_id=task_id,
                strategy_id=strategy_id,
                target_type=target_type,
                outcome=outcome,
                details=details,
            )
        except TypeError:
            return payload


# --------------------------------------------------------------------------- #
# 延遲匯入 helper（僅 VM 上引擎可匯入時生效）
# --------------------------------------------------------------------------- #
def _import_bounty_models():
    from app.bounty import models as m  # noqa: WPS433
    return m


def _import_wallet_schemas():
    from eliana_digital_wallet.models import schemas as m  # noqa: WPS433
    return m


def _import_learning_models():
    from src import models as m  # noqa: WPS433
    return m


def _first_scope(program: dict) -> str:
    for key in ("scope_in", "domains", "scope"):
        vals = program.get(key)
        if isinstance(vals, list) and vals:
            return str(vals[0])
        if isinstance(vals, str) and vals:
            return vals
    return str(program.get("target_url", ""))
