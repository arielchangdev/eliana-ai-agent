"""Dashboard REST API 端點。"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from ..models import NotificationPreferences
from ..services.data_aggregator import _knowledge_to_dict, _metrics_to_dict


@dataclass
class DashboardComponents:
    """Dashboard 各服務的容器。"""

    aggregator: Any = None
    notification_engine: Any = None
    ws_manager: Any = None
    db: Any = None


class NotificationPreferencesRequest(BaseModel):
    enabled_categories: list[str] = ["all"]
    mute_start_hour: Optional[int] = None
    mute_end_hour: Optional[int] = None
    urgent_override_mute: bool = True


def create_rest_router(components: DashboardComponents) -> APIRouter:
    router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

    @router.get("/snapshot")
    async def get_snapshot():
        if components.aggregator is None:
            raise HTTPException(status_code=503, detail="Aggregator 未初始化")
        snapshot = await components.aggregator.get_full_snapshot()
        return _snapshot_to_dict(snapshot)

    @router.get("/tasks")
    async def get_tasks(
        limit: int = 100,
        status: Optional[str] = Query(None),
        keyword: Optional[str] = Query(None),
    ):
        if components.aggregator is None:
            raise HTTPException(status_code=503, detail="Aggregator 未初始化")
        tasks = await components.aggregator.get_task_timeline(
            limit=limit, status_filter=status, keyword=keyword
        )
        from ..services.data_aggregator import _task_to_dict, compute_success_rate
        return {
            "tasks": [_task_to_dict(t) for t in tasks],
            "success_rate_24h": compute_success_rate(tasks, 24),
            "success_rate_7d": compute_success_rate(tasks, 24 * 7),
        }

    @router.get("/metrics/{host}/history")
    async def get_metrics_history(host: str, hours: int = 1):
        if components.aggregator is None:
            raise HTTPException(status_code=503, detail="Aggregator 未初始化")
        metrics = components.aggregator.get_latest_metrics()
        m = metrics.get(host)
        if m is None:
            raise HTTPException(status_code=404, detail=f"未知主機: {host}")
        # 歷史趨勢資料整合階段接真實時序來源；此處回傳當前值
        return {"host": host, "hours": hours,
                "current": _metrics_to_dict(m), "history": []}

    @router.get("/knowledge")
    async def get_knowledge():
        if components.aggregator is None:
            raise HTTPException(status_code=503, detail="Aggregator 未初始化")
        stats = await components.aggregator.poll_knowledge_stats()
        if stats is None:
            return {"available": False}
        return {"available": True, **_knowledge_to_dict(stats)}

    @router.put("/notifications/preferences")
    async def update_preferences(req: NotificationPreferencesRequest):
        if components.notification_engine is None:
            raise HTTPException(status_code=503, detail="NotificationEngine 未初始化")
        prefs = NotificationPreferences(
            enabled_categories=req.enabled_categories,
            mute_start_hour=req.mute_start_hour,
            mute_end_hour=req.mute_end_hour,
            urgent_override_mute=req.urgent_override_mute,
        )
        components.notification_engine.update_preferences(prefs)
        return {
            "enabled_categories": prefs.enabled_categories,
            "mute_start_hour": prefs.mute_start_hour,
            "mute_end_hour": prefs.mute_end_hour,
            "urgent_override_mute": prefs.urgent_override_mute,
        }

    return router


def _snapshot_to_dict(s) -> dict:
    return {
        "agentState": s.agent_state.value if hasattr(s.agent_state, "value") else str(s.agent_state),
        "currentTaskName": s.current_task_name,
        "currentTaskProgress": s.current_task_progress,
        "resources": s.resources,
        "recentTasks": s.recent_tasks,
        "knowledgeStats": s.knowledge_stats,
        "activeAlerts": s.active_alerts,
        "timestamp": s.timestamp.isoformat(),
    }
