"""Pipeline_Orchestrator — 端對端流程編排器。

按 SEARCH → AUTHORIZE → SCAN → REPORT → TRACK_BOUNTY 順序編排。
每次啟動建立唯一 pipeline_id (uuid4)，追蹤每階段狀態。
任一階段失敗即停止後續（後續維持 pending），發布 pipeline_failed 事件。
掃描發現漏洞時觸發 REPORT；每次結果回饋 Learning_Engine 的 Strategy_Optimizer。

階段執行邏輯透過注入的 stage handler（Callable）提供，使外部子系統可 mock。
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Awaitable, Callable

import structlog

from .event_bus import EventBus
from .models import (
    STAGE_ORDER,
    Event,
    PipelineRun,
    PipelineStage,
    StageStatus,
)

logger = structlog.get_logger(__name__)

# 階段處理器：接收 (PipelineRun, 上一階段輸出) → 回傳本階段輸出 dict
StageHandler = Callable[[PipelineRun, dict], Awaitable[dict]]

TOPIC_PIPELINE_FAILED = "pipeline.failed"
TOPIC_PIPELINE_COMPLETED = "pipeline.completed"
TOPIC_STRATEGY_FEEDBACK = "learning.strategy_feedback"
TOPIC_REPORT_TRIGGER = "report.generate"


def _now() -> datetime:
    return datetime.now(timezone.utc)


class PipelineOrchestrator:
    """協調端對端紅隊流程。"""

    def __init__(
        self,
        event_bus: EventBus,
        handlers: dict[PipelineStage, StageHandler] | None = None,
    ) -> None:
        self._bus = event_bus
        self._handlers: dict[PipelineStage, StageHandler] = handlers or {}
        self._runs: dict[str, PipelineRun] = {}

    def register_handler(self, stage: PipelineStage, handler: StageHandler) -> None:
        self._handlers[stage] = handler

    def get_pipeline_status(self, pipeline_id: str) -> PipelineRun | None:
        return self._runs.get(pipeline_id)

    async def cancel_pipeline(self, pipeline_id: str) -> None:
        run = self._runs.get(pipeline_id)
        if run and run.status in (StageStatus.PENDING, StageStatus.RUNNING):
            run.status = StageStatus.SKIPPED
            for sr in run.stages:
                if sr.status in (StageStatus.PENDING, StageStatus.RUNNING):
                    sr.status = StageStatus.SKIPPED

    async def start_pipeline(self, target: dict | None = None) -> PipelineRun:
        """啟動一次新流程，同步執行至完成或失敗後回傳最終狀態。"""
        run = PipelineRun(target=target or {})
        self._runs[run.pipeline_id] = run
        run.status = StageStatus.RUNNING

        prev_output: dict = {}
        vuln_found = False

        for stage in STAGE_ORDER:
            sr = run.stage(stage)
            sr.status = StageStatus.RUNNING
            sr.started_at = _now()
            try:
                handler = self._handlers.get(stage, self._noop_handler)
                output = await handler(run, prev_output)
                sr.output = output or {}
                sr.status = StageStatus.COMPLETED
                sr.completed_at = _now()
                prev_output = sr.output

                # SCAN 階段判定是否發現漏洞 → 觸發 REPORT
                if stage == PipelineStage.SCAN:
                    vuln_found = bool(sr.output.get("vulnerabilities"))
                    if vuln_found:
                        await self._bus.publish_and_wait(Event(
                            topic=TOPIC_REPORT_TRIGGER,
                            source="pipeline",
                            payload={"pipeline_id": run.pipeline_id,
                                     "vulnerabilities": sr.output.get("vulnerabilities")},
                        ))
            except Exception as exc:  # noqa: BLE001
                sr.status = StageStatus.FAILED
                sr.completed_at = _now()
                sr.error = str(exc)
                run.status = StageStatus.FAILED
                run.failed_stage = stage
                # 後續階段維持 pending（不動）
                await self._bus.publish_and_wait(Event(
                    topic=TOPIC_PIPELINE_FAILED,
                    source="pipeline",
                    payload={"pipeline_id": run.pipeline_id,
                             "stage": stage.value, "error": str(exc)},
                ))
                await self._feedback(run, success=False, vuln_found=vuln_found)
                logger.warning("pipeline_failed", pipeline_id=run.pipeline_id,
                               stage=stage.value, error=str(exc))
                return run

        run.status = StageStatus.COMPLETED
        await self._bus.publish_and_wait(Event(
            topic=TOPIC_PIPELINE_COMPLETED,
            source="pipeline",
            payload={"pipeline_id": run.pipeline_id, "vuln_found": vuln_found},
        ))
        await self._feedback(run, success=True, vuln_found=vuln_found)
        return run

    async def _feedback(self, run: PipelineRun, *, success: bool, vuln_found: bool) -> None:
        """將流程結果回饋至 Learning_Engine 的 Strategy_Optimizer。"""
        await self._bus.publish_and_wait(Event(
            topic=TOPIC_STRATEGY_FEEDBACK,
            source="pipeline",
            payload={
                "pipeline_id": run.pipeline_id,
                "success": success,
                "vuln_found": vuln_found,
                "failed_stage": run.failed_stage.value if run.failed_stage else None,
            },
        ))

    @staticmethod
    async def _noop_handler(run: PipelineRun, prev: dict) -> dict:
        return {}
