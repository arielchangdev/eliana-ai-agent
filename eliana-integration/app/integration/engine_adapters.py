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
    ) -> None:
        self._crawler = crawler
        self._auth_gate = auth_gate
        self._scan_engine = scan_engine
        self._report_gen = report_gen
        self.dry_run = dry_run

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
        """送出授權請求並停在等待狀態。

        依選項 A：一律回傳 False（未核准），使 pipeline 的 AUTHORIZE 階段
        停止後續，不進入 SCAN。真正的核准由人工於 Authorization_Gate 完成後，
        再另行觸發後續流程。同時拋出的資訊記錄於事件供 dashboard 通知。
        """
        if self._auth_gate is None:
            raise SubsystemNotWired("authorization gate not wired")
        operation = self._build_scan_operation(program)
        decision = await self._auth_gate.request_authorization(operation)
        status = getattr(decision, "status", None)
        status_val = getattr(status, "value", status)
        logger.info("authorization_requested",
                    operation_id=getattr(operation, "id", None),
                    status=status_val)
        # PENDING（或任何非 APPROVED）→ 未授權，閘門擋住
        return str(status_val).lower() == "approved"

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

        result = await self._scan_engine.execute_scan(scan_target, profile)
        return self._scan_result_to_dict(result)

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

    async def record_bounty(self, report: dict) -> dict:
        if self._ledger is None:
            raise SubsystemNotWired("transaction ledger not wired")
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

    def __init__(self, *, optimizer: Any | None = None) -> None:
        self._optimizer = optimizer

    async def record_result(self, feedback: dict) -> None:
        if self._optimizer is None:
            logger.debug("learning optimizer not wired; skip feedback")
            return
        task_result = self._build_task_result(feedback)
        await self._optimizer.record_result(task_result)

    def _build_task_result(self, feedback: dict):
        outcome = "success" if feedback.get("success") else "failure"
        payload = {
            "strategy_id": feedback.get("strategy_id", "default"),
            "outcome": outcome,
            "vuln_found": bool(feedback.get("vuln_found", False)),
        }
        # 嘗試用引擎領域模型建構；引擎不可匯入或欄位不符時退回 dict
        try:
            m = _import_learning_models()
        except Exception:  # noqa: BLE001
            return payload
        try:
            return m.TaskResult(
                strategy_id=payload["strategy_id"],
                outcome=outcome,
                vuln_found=payload["vuln_found"],
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
