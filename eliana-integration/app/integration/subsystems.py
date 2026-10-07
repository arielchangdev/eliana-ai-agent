"""子系統埠口介面（Ports）與真實接線層。

本模組定義整合層對六個子系統的**最小依賴介面**（Protocol），並提供：
- 真實 pipeline stage handlers（接 bounty-hunter / digital-wallet / learning-engine）
- 真實 adapter backends 的組裝

設計原則：整合層只依賴這些 Protocol，不直接 import 各引擎的實作模組。VM 啟動
腳本負責建立真實引擎物件並注入。若某引擎尚未接上（None），對應 handler 會拋出
明確的 SubsystemNotWired 錯誤（pipeline 會據此標記該階段失敗），而非靜默崩潰。

如此一來，不論各引擎在 VM 上的實際 import 路徑為何，本接線層都不需改動。
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

import structlog

from .models import PipelineRun, PipelineStage
from .pipeline import StageHandler

logger = structlog.get_logger(__name__)


class SubsystemNotWired(RuntimeError):
    """階段所需的子系統尚未注入真實實作。"""


# --------------------------------------------------------------------------- #
# 子系統埠口介面（整合層僅依賴這些）
# --------------------------------------------------------------------------- #
@runtime_checkable
class BountyHunterPort(Protocol):
    async def search_programs(self, criteria: dict) -> list[dict]:
        """搜尋 Bug Bounty 計畫，回傳計畫清單。"""
        ...

    async def request_authorization(self, program: dict) -> bool:
        """請求人工授權，回傳是否已授權。"""
        ...

    async def run_scan(self, target: dict) -> dict:
        """執行掃描（經 SSH → Kali 工具），回傳結果（含 vulnerabilities）。"""
        ...

    async def generate_report(self, scan_result: dict) -> dict:
        """依掃描結果生成漏洞報告。"""
        ...


@runtime_checkable
class WalletPort(Protocol):
    async def record_bounty(self, report: dict) -> dict:
        """記錄獎金入帳交易，回傳交易紀錄。"""
        ...


@runtime_checkable
class LearningPort(Protocol):
    async def record_result(self, feedback: dict) -> None:
        """回饋流程結果供策略優化。"""
        ...


# --------------------------------------------------------------------------- #
# 真實 stage handlers
# --------------------------------------------------------------------------- #
def _require(obj: Any, stage: PipelineStage):
    if obj is None:
        raise SubsystemNotWired(
            f"stage '{stage.value}' requires a wired subsystem, got None"
        )
    return obj


def build_pipeline_handlers(
    *,
    bounty: BountyHunterPort | None = None,
    wallet: WalletPort | None = None,
) -> dict[PipelineStage, StageHandler]:
    """組裝五階段真實 handlers。未注入的子系統對應階段會在執行時拋 SubsystemNotWired。

    SEARCH/AUTHORIZE/SCAN/REPORT → bounty；TRACK_BOUNTY → wallet。
    """

    async def search(run: PipelineRun, prev: dict) -> dict:
        bh = _require(bounty, PipelineStage.SEARCH)
        programs = await bh.search_programs(run.target or {})
        return {"programs": programs}

    async def authorize(run: PipelineRun, prev: dict) -> dict:
        bh = _require(bounty, PipelineStage.AUTHORIZE)
        programs = prev.get("programs") or []
        target_program = programs[0] if programs else run.target
        authorized = await bh.request_authorization(target_program)
        if not authorized:
            # 未授權 → 視為階段失敗，pipeline 停止後續（符合授權閘門語意）
            raise PermissionError("authorization not granted; scan blocked")
        return {"authorized": True, "program": target_program}

    async def scan(run: PipelineRun, prev: dict) -> dict:
        bh = _require(bounty, PipelineStage.SCAN)
        target = prev.get("program") or run.target
        result = await bh.run_scan(target)
        # result 需含 'vulnerabilities' key 才會觸發 REPORT（見 orchestrator）
        return result if isinstance(result, dict) else {"raw": result}

    async def report(run: PipelineRun, prev: dict) -> dict:
        bh = _require(bounty, PipelineStage.REPORT)
        report_doc = await bh.generate_report(prev)
        return {"report": report_doc}

    async def track_bounty(run: PipelineRun, prev: dict) -> dict:
        w = _require(wallet, PipelineStage.TRACK_BOUNTY)
        tx = await w.record_bounty(prev.get("report") or {})
        return {"transaction": tx}

    return {
        PipelineStage.SEARCH: search,
        PipelineStage.AUTHORIZE: authorize,
        PipelineStage.SCAN: scan,
        PipelineStage.REPORT: report,
        PipelineStage.TRACK_BOUNTY: track_bounty,
    }


# --------------------------------------------------------------------------- #
# 策略回饋訂閱者（把 pipeline 的 learning.strategy_feedback 事件送進 learning engine）
# --------------------------------------------------------------------------- #
def make_strategy_feedback_subscriber(learning: LearningPort | None):
    """回傳一個 async event handler，訂閱 learning.strategy_feedback 用。"""

    async def handler(event) -> None:
        if learning is None:
            logger.debug("learning_not_wired_skip_feedback")
            return
        await learning.record_result(event.payload)

    return handler
