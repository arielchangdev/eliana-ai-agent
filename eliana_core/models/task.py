"""任務相關資料模型."""

from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import uuid


class TaskPriority(Enum):
    """任務優先順序。"""
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3


class TaskStatus(Enum):
    """任務狀態。"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class HostTarget(Enum):
    """目標主機。"""
    CORE = "core_host"
    WEAPON = "weapon_host"


class TaskCategory(Enum):
    """任務類別，決定派送目標。"""
    SECURITY_TOOL = "security_tool"      # -> Weapon_Host
    RECONNAISSANCE = "reconnaissance"    # -> Weapon_Host
    EXPLOITATION = "exploitation"        # -> Weapon_Host
    COMPUTATION = "computation"          # -> Core_Host
    LLM_INFERENCE = "llm_inference"      # -> Core_Host
    ANALYSIS = "analysis"                # -> Core_Host


@dataclass
class Task:
    """任務資料模型。"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    priority: TaskPriority = TaskPriority.NORMAL
    category: TaskCategory = TaskCategory.COMPUTATION
    status: TaskStatus = TaskStatus.PENDING
    dependencies: list[str] = field(default_factory=list)
    payload: dict = field(default_factory=dict)
    retry_count: int = 0
    max_retries: int = 3
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
