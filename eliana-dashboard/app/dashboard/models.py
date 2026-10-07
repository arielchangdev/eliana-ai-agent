"""後端資料模型與列舉型別。

所有時間戳使用 UTC。dataclass 對應 design.md 的 Data Models。
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class AgentState(Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"


class NotificationPriority(Enum):
    URGENT = "urgent"   # 立即發送
    NORMAL = "normal"   # 每 5 分鐘批次
    LOW = "low"         # 每 30 分鐘批次


class TaskResultStatus(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    RUNNING = "running"


class CommandType(Enum):
    SCAN = "scan"
    PAUSE = "pause"
    RESUME = "resume"
    STOP = "stop"
    STATUS = "status"


class AuthorizationDecision(Enum):
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"


# --------------------------------------------------------------------------- #
# Dataclasses
# --------------------------------------------------------------------------- #
@dataclass
class SystemMetrics:
    """單一主機資源指標。"""
    host: str
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_used_gb: float = 0.0
    memory_total_gb: float = 0.0
    disk_percent: float = 0.0
    disk_used_gb: float = 0.0
    disk_total_gb: float = 0.0
    timestamp: datetime = field(default_factory=_utcnow)
    stale: bool = False


@dataclass
class TaskTimelineItem:
    task_id: str
    name: str
    status: TaskResultStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    target: Optional[str] = None
    strategy: Optional[str] = None
    error_message: Optional[str] = None
    output_summary: Optional[str] = None


@dataclass
class KnowledgeStats:
    total_fragments: int = 0
    category_distribution: dict = field(default_factory=dict)
    daily_growth: list = field(default_factory=list)
    last_crawl_time: Optional[datetime] = None
    last_crawl_status: Optional[str] = None
    next_crawl_time: Optional[datetime] = None
    strategy_summary: dict = field(default_factory=dict)


@dataclass
class ResourceAlert:
    host: str
    metric_name: str
    current_value: float
    threshold_value: float
    duration_seconds: int = 0
    triggered_at: datetime = field(default_factory=_utcnow)


@dataclass
class DashboardSnapshot:
    agent_state: AgentState
    current_task_name: Optional[str] = None
    current_task_progress: float = 0.0
    resources: dict = field(default_factory=dict)
    recent_tasks: list = field(default_factory=list)
    knowledge_stats: Optional[dict] = None
    active_alerts: list = field(default_factory=list)
    timestamp: datetime = field(default_factory=_utcnow)


@dataclass
class DashboardMessage:
    """WebSocket 推送訊息。type: agent_status|resource_update|task_update|
    knowledge_update|alert|snapshot。"""
    type: str
    payload: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=_utcnow)


@dataclass
class Notification:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    priority: NotificationPriority = NotificationPriority.NORMAL
    event_type: str = ""
    title: str = ""
    summary: str = ""
    link: Optional[str] = None
    created_at: datetime = field(default_factory=_utcnow)
    sent_at: Optional[datetime] = None


@dataclass
class RemoteCommand:
    command_type: CommandType
    args: list = field(default_factory=list)
    user_id: int = 0
    raw_text: str = ""
    received_at: datetime = field(default_factory=_utcnow)


@dataclass
class AuthorizationRequest:
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    operation_description: str = ""
    target: str = ""
    risk_level: str = ""
    requested_at: datetime = field(default_factory=_utcnow)
    expires_at: Optional[datetime] = None
    decision: Optional[AuthorizationDecision] = None
    decided_at: Optional[datetime] = None
    decided_by: Optional[int] = None


@dataclass
class NotificationPreferences:
    enabled_categories: list = field(default_factory=lambda: ["all"])
    mute_start_hour: Optional[int] = None
    mute_end_hour: Optional[int] = None
    urgent_override_mute: bool = True


@dataclass
class AuditLogEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = ""
    user_id: Optional[int] = None
    details: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=_utcnow)


@dataclass
class AgentStatus:
    """供 /status 回覆使用的當前狀態。"""
    state: AgentState
    current_task_name: Optional[str] = None
    current_task_progress: float = 0.0
