"""整合模組資料模型（Pydantic v2）。

涵蓋事件、健康狀態、Pipeline 階段與執行、驗證結果、套件授權等資料結構。
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return str(uuid.uuid4())


# --------------------------------------------------------------------------- #
# 事件
# --------------------------------------------------------------------------- #
class Event(BaseModel):
    """Event_Bus 傳遞的事件單元。"""

    event_id: str = Field(default_factory=_new_id)
    topic: str
    payload: dict[str, Any] = Field(default_factory=dict)
    source: str = "unknown"
    timestamp: datetime = Field(default_factory=_utcnow)
    # 重試相關（Event_Bus 內部使用）
    retry_count: int = 0


# --------------------------------------------------------------------------- #
# 健康狀態
# --------------------------------------------------------------------------- #
class HealthState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class ModuleHealth(BaseModel):
    """單一子模組的健康狀態。"""

    module: str
    state: HealthState = HealthState.HEALTHY
    last_checked: datetime = Field(default_factory=_utcnow)
    error: str | None = None


class HealthStatus(BaseModel):
    """整體系統健康彙總。"""

    overall: HealthState = HealthState.HEALTHY
    modules: list[ModuleHealth] = Field(default_factory=list)
    checked_at: datetime = Field(default_factory=_utcnow)

    @property
    def http_status(self) -> int:
        """全部 healthy → 200；任一 unhealthy → 503。"""
        if any(m.state == HealthState.UNHEALTHY for m in self.modules):
            return 503
        return 200


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #
class PipelineStage(str, Enum):
    SEARCH = "search"
    AUTHORIZE = "authorize"
    SCAN = "scan"
    REPORT = "report"
    TRACK_BOUNTY = "track_bounty"


# 端對端流程的固定順序
STAGE_ORDER: list[PipelineStage] = [
    PipelineStage.SEARCH,
    PipelineStage.AUTHORIZE,
    PipelineStage.SCAN,
    PipelineStage.REPORT,
    PipelineStage.TRACK_BOUNTY,
]


class StageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class StageRun(BaseModel):
    """單一階段的執行紀錄。"""

    stage: PipelineStage
    status: StageStatus = StageStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    output: dict[str, Any] = Field(default_factory=dict)


class PipelineRun(BaseModel):
    """一次完整 Pipeline 執行的狀態容器。"""

    pipeline_id: str = Field(default_factory=_new_id)
    target: dict[str, Any] = Field(default_factory=dict)
    stages: list[StageRun] = Field(
        default_factory=lambda: [StageRun(stage=s) for s in STAGE_ORDER]
    )
    status: StageStatus = StageStatus.PENDING
    created_at: datetime = Field(default_factory=_utcnow)
    failed_stage: PipelineStage | None = None

    def stage(self, stage: PipelineStage) -> StageRun:
        for sr in self.stages:
            if sr.stage == stage:
                return sr
        raise KeyError(stage)


# --------------------------------------------------------------------------- #
# 啟動驗證
# --------------------------------------------------------------------------- #
class ValidationResult(BaseModel):
    """單一依賴元件的啟動驗證結果。"""

    component: str
    passed: bool
    error: str | None = None
    duration_ms: float = 0.0


# --------------------------------------------------------------------------- #
# 授權掃描
# --------------------------------------------------------------------------- #
class PackageLicense(BaseModel):
    """單一 Python 套件的授權資訊。"""

    name: str
    version: str = "unknown"
    license: str = "UNKNOWN"
    compliant: bool = True
