"""Data Aggregator：彙整各模組狀態資料。

外部資料來源（core-infra Resource_Monitor / Task_Scheduler、learning-engine
知識庫統計）以注入式 provider 提供，便於測試以 mock 替代。
核心判斷（成功率、資源告警、任務過濾）為純函式，供 property test 驗證。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from ..models import (
    AgentState,
    DashboardSnapshot,
    KnowledgeStats,
    ResourceAlert,
    SystemMetrics,
    TaskResultStatus,
    TaskTimelineItem,
)

# 告警閾值
CPU_THRESHOLD = 90.0
MEMORY_THRESHOLD = 85.0
# 資料過期判定（秒）
STALE_SECONDS = 30


class DataAggregator:
    def __init__(
        self,
        resource_provider=None,
        task_provider=None,
        knowledge_provider=None,
        agent_state_provider=None,
    ):
        self._resource_provider = resource_provider
        self._task_provider = task_provider
        self._knowledge_provider = knowledge_provider
        self._agent_state_provider = agent_state_provider
        # 最近一次各主機指標快取
        self._latest_metrics: dict[str, SystemMetrics] = {}

    def update_metrics(self, metrics: SystemMetrics) -> None:
        """接收 Resource_Monitor 推送的新指標。"""
        self._latest_metrics[metrics.host] = metrics

    def get_latest_metrics(self, now: Optional[datetime] = None) -> dict[str, SystemMetrics]:
        """回傳各主機最新指標，超過 STALE_SECONDS 未更新標記 stale。"""
        current = now or datetime.now(timezone.utc)
        result: dict[str, SystemMetrics] = {}
        for host, m in self._latest_metrics.items():
            age = (current - m.timestamp).total_seconds()
            m.stale = age > STALE_SECONDS
            result[host] = m
        return result

    async def get_task_timeline(
        self, limit: int = 100, status_filter: Optional[str] = None,
        keyword: Optional[str] = None,
    ) -> list[TaskTimelineItem]:
        """查詢任務時間線資料並套用過濾。"""
        tasks: list[TaskTimelineItem] = []
        if self._task_provider is not None:
            tasks = await _maybe_await(self._task_provider())
        return filter_tasks(tasks, status_filter, keyword, limit)

    async def poll_knowledge_stats(self) -> Optional[KnowledgeStats]:
        """輪詢 learning-engine 知識庫統計。"""
        if self._knowledge_provider is None:
            return None
        return await _maybe_await(self._knowledge_provider())

    async def get_full_snapshot(self) -> DashboardSnapshot:
        """產生完整狀態快照（供新連線客戶端）。"""
        agent_state = AgentState.IDLE
        current_task = None
        progress = 0.0
        if self._agent_state_provider is not None:
            status = await _maybe_await(self._agent_state_provider())
            agent_state = status.state
            current_task = status.current_task_name
            progress = status.current_task_progress

        metrics = self.get_latest_metrics()
        tasks = await self.get_task_timeline(limit=100)
        knowledge = await self.poll_knowledge_stats()
        alerts = [a for a in (
            evaluate_resource_alert(m, {}) for m in metrics.values()
        ) if a is not None]

        return DashboardSnapshot(
            agent_state=agent_state,
            current_task_name=current_task,
            current_task_progress=progress,
            resources={h: _metrics_to_dict(m) for h, m in metrics.items()},
            recent_tasks=[_task_to_dict(t) for t in tasks],
            knowledge_stats=_knowledge_to_dict(knowledge) if knowledge else None,
            active_alerts=[_alert_to_dict(a) for a in alerts],
        )

    def compute_success_rate(
        self, tasks: list[TaskTimelineItem], hours: int
    ) -> float:
        return compute_success_rate(tasks, hours)

    def evaluate_resource_alert(
        self, metrics: SystemMetrics, threshold_config: dict
    ) -> Optional[ResourceAlert]:
        return evaluate_resource_alert(metrics, threshold_config)


# --------------------------------------------------------------------------- #
# 純函式（供 property test 直接驗證）
# --------------------------------------------------------------------------- #
def evaluate_resource_alert(
    metrics: SystemMetrics, threshold_config: dict
) -> Optional[ResourceAlert]:
    """評估資源指標是否觸發告警。

    CPU >= 90% 或 memory >= 85% 觸發；優先回報 CPU（若兩者皆超標）。
    未超標回傳 None。
    """
    cpu_thresh = threshold_config.get("cpu", CPU_THRESHOLD)
    mem_thresh = threshold_config.get("memory", MEMORY_THRESHOLD)

    if metrics.cpu_percent >= cpu_thresh:
        return ResourceAlert(
            host=metrics.host, metric_name="cpu",
            current_value=metrics.cpu_percent, threshold_value=cpu_thresh,
        )
    if metrics.memory_percent >= mem_thresh:
        return ResourceAlert(
            host=metrics.host, metric_name="memory",
            current_value=metrics.memory_percent, threshold_value=mem_thresh,
        )
    return None


def compute_success_rate(tasks: list[TaskTimelineItem], hours: int) -> float:
    """計算指定時間窗口內的任務成功率。

    分母 = start_time 落在 [now - hours, now] 內的任務數；
    分子 = 其中 status == SUCCESS 的任務數。窗口內無任務回傳 0.0。
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=hours)
    in_window = [
        t for t in tasks
        if _aware(t.start_time) >= cutoff and _aware(t.start_time) <= now
    ]
    if not in_window:
        return 0.0
    successes = sum(1 for t in in_window if t.status == TaskResultStatus.SUCCESS)
    return successes / len(in_window)


def filter_tasks(
    tasks: list[TaskTimelineItem], status_filter: Optional[str],
    keyword: Optional[str], limit: int = 100,
) -> list[TaskTimelineItem]:
    """依 status 與 keyword 過濾任務；結果須同時滿足所有指定條件。"""
    result = []
    for t in tasks:
        if status_filter is not None:
            status_val = (
                t.status.value if hasattr(t.status, "value") else str(t.status)
            )
            if status_val != status_filter:
                continue
        if keyword is not None:
            if keyword.lower() not in t.name.lower():
                continue
        result.append(t)
    return result[:limit]


# --------------------------------------------------------------------------- #
# helper
# --------------------------------------------------------------------------- #
def _aware(dt: datetime) -> datetime:
    """確保 datetime 帶時區（視 naive 為 UTC）。"""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


async def _maybe_await(value):
    import asyncio
    if asyncio.iscoroutine(value):
        return await value
    return value


def _metrics_to_dict(m: SystemMetrics) -> dict:
    return {
        "host": m.host, "cpuPercent": m.cpu_percent,
        "memoryPercent": m.memory_percent, "memoryUsedGb": m.memory_used_gb,
        "memoryTotalGb": m.memory_total_gb, "diskPercent": m.disk_percent,
        "diskUsedGb": m.disk_used_gb, "diskTotalGb": m.disk_total_gb,
        "timestamp": m.timestamp.isoformat(), "stale": m.stale,
    }


def _task_to_dict(t: TaskTimelineItem) -> dict:
    return {
        "taskId": t.task_id, "name": t.name,
        "status": t.status.value if hasattr(t.status, "value") else str(t.status),
        "startTime": t.start_time.isoformat(),
        "endTime": t.end_time.isoformat() if t.end_time else None,
        "durationSeconds": t.duration_seconds, "target": t.target,
        "strategy": t.strategy, "errorMessage": t.error_message,
        "outputSummary": t.output_summary,
    }


def _knowledge_to_dict(k: KnowledgeStats) -> dict:
    return {
        "totalFragments": k.total_fragments,
        "categoryDistribution": k.category_distribution,
        "dailyGrowth": k.daily_growth,
        "lastCrawlTime": k.last_crawl_time.isoformat() if k.last_crawl_time else None,
        "lastCrawlStatus": k.last_crawl_status,
        "nextCrawlTime": k.next_crawl_time.isoformat() if k.next_crawl_time else None,
        "strategySummary": k.strategy_summary,
    }


def _alert_to_dict(a: ResourceAlert) -> dict:
    return {
        "host": a.host, "metricName": a.metric_name,
        "currentValue": a.current_value, "thresholdValue": a.threshold_value,
        "durationSeconds": a.duration_seconds,
        "triggeredAt": a.triggered_at.isoformat(),
    }
