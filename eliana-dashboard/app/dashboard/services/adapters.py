"""外部依賴介面 adapter 與 mock。

Dashboard 依賴 core-infra（Resource_Monitor、Task_Scheduler）、
bounty-hunter（Authorization_Gate）、learning-engine（知識庫統計）。
本模組定義注入式 Protocol，並提供開發/測試用 mock adapter。
真實 adapter 於整合階段（VM 上）接各引擎實際介面。
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from ..models import (
    AgentState,
    AgentStatus,
    KnowledgeStats,
    SystemMetrics,
    TaskResultStatus,
    TaskTimelineItem,
)


# --------------------------------------------------------------------------- #
# 注入式 Protocol
# --------------------------------------------------------------------------- #
@runtime_checkable
class ResourceMonitorClient(Protocol):
    """core-infra Resource_Monitor 訂閱介面。"""

    async def get_metrics(self) -> list[SystemMetrics]:
        ...


@runtime_checkable
class TaskSchedulerClient(Protocol):
    """core-infra Task_Scheduler 指令轉發介面。"""

    async def dispatch_command(self, command_type: str, args: list) -> dict:
        ...

    async def get_recent_tasks(self, limit: int = 100) -> list[TaskTimelineItem]:
        ...

    async def get_agent_status(self) -> AgentStatus:
        ...


@runtime_checkable
class KnowledgeStatsClient(Protocol):
    """learning-engine 知識庫統計介面。"""

    async def get_stats(self) -> KnowledgeStats:
        ...


# --------------------------------------------------------------------------- #
# Mock adapter（開發 / 測試用）
# --------------------------------------------------------------------------- #
class MockResourceMonitor:
    """回傳固定雙機指標的 mock。"""

    def __init__(self, rhel_cpu: float = 45.0, kali_cpu: float = 30.0):
        self.rhel_cpu = rhel_cpu
        self.kali_cpu = kali_cpu

    async def get_metrics(self) -> list[SystemMetrics]:
        now = datetime.now(timezone.utc)
        return [
            SystemMetrics(host="rhel-10", cpu_percent=self.rhel_cpu,
                          memory_percent=60.0, disk_percent=40.0, timestamp=now),
            SystemMetrics(host="kali", cpu_percent=self.kali_cpu,
                          memory_percent=35.0, disk_percent=25.0, timestamp=now),
        ]


class MockTaskScheduler:
    """記錄派送指令並回傳固定任務的 mock。"""

    def __init__(self):
        self.dispatched: list[tuple[str, list]] = []

    async def dispatch_command(self, command_type: str, args: list) -> dict:
        self.dispatched.append((command_type, args))
        return {"success": True, "command": command_type, "affected": "task-1"}

    async def get_recent_tasks(self, limit: int = 100) -> list[TaskTimelineItem]:
        now = datetime.now(timezone.utc)
        return [
            TaskTimelineItem("t1", "scan alpha", TaskResultStatus.SUCCESS, now),
            TaskTimelineItem("t2", "scan beta", TaskResultStatus.RUNNING, now),
        ][:limit]

    async def get_agent_status(self) -> AgentStatus:
        return AgentStatus(state=AgentState.RUNNING,
                           current_task_name="scan alpha",
                           current_task_progress=0.6)


class MockKnowledgeStats:
    async def get_stats(self) -> KnowledgeStats:
        return KnowledgeStats(
            total_fragments=128,
            category_distribution={
                "vulnerability_type": 50, "tool_usage": 30,
                "attack_technique": 28, "defense_bypass": 20,
            },
            last_crawl_time=datetime.now(timezone.utc),
            last_crawl_status="success",
            strategy_summary={"total": 12, "highEfficiency": 5, "needsOptimization": 3},
        )
