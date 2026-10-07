"""系統監控相關資料模型."""

from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import uuid

from .task import HostTarget


class AlertLevel(Enum):
    """告警級別。"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class SystemMetrics:
    """系統指標資料模型。"""
    host: HostTarget
    cpu_percent: float          # 0.0 ~ 100.0
    memory_percent: float       # 0.0 ~ 100.0
    memory_used_gb: float
    memory_total_gb: float
    disk_percent: float         # 0.0 ~ 100.0
    disk_used_gb: float
    disk_total_gb: float
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class DirUsage:
    """目錄空間使用量。"""
    path: str
    size_gb: float


@dataclass
class Alert:
    """告警資料模型。"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    level: AlertLevel = AlertLevel.INFO
    host: HostTarget = HostTarget.CORE
    metric_name: str = ""
    current_value: float = 0.0
    threshold_value: float = 0.0
    message: str = ""
    triggered_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
