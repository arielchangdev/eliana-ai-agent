"""監控 API 端點.

實作 GET /metrics/{host}、GET /metrics/{host}/history、GET /alerts 端點，
提供系統指標查詢與告警功能。
"""

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from eliana_core.db.database import DatabasePool, get_db
from eliana_core.models.metrics import (
    Alert as AlertDataclass,
    AlertLevel,
    SystemMetrics as SystemMetricsDataclass,
)
from eliana_core.models.task import HostTarget
from eliana_core.services.resource_monitor import ResourceMonitor


router = APIRouter()
alerts_router = APIRouter()


# --- Pydantic Schemas ---


class SystemMetricsResponse(BaseModel):
    """系統指標回應 schema."""

    host: HostTarget = Field(..., description="目標主機")
    cpu_percent: float = Field(..., description="CPU 使用率 (0.0 ~ 100.0)")
    memory_percent: float = Field(..., description="記憶體使用率 (0.0 ~ 100.0)")
    memory_used_gb: float = Field(..., description="已使用記憶體 (GB)")
    memory_total_gb: float = Field(..., description="總記憶體 (GB)")
    disk_percent: float = Field(..., description="磁碟使用率 (0.0 ~ 100.0)")
    disk_used_gb: float = Field(..., description="已使用磁碟空間 (GB)")
    disk_total_gb: float = Field(..., description="總磁碟空間 (GB)")
    timestamp: datetime = Field(..., description="採集時間")


class AlertResponse(BaseModel):
    """告警回應 schema."""

    id: str = Field(..., description="告警 ID")
    level: AlertLevel = Field(..., description="告警級別")
    host: HostTarget = Field(..., description="告警主機")
    metric_name: str = Field(..., description="觸發指標名稱")
    current_value: float = Field(..., description="當前指標值")
    threshold_value: float = Field(..., description="閾值")
    message: str = Field(..., description="告警訊息")
    triggered_at: datetime = Field(..., description="觸發時間")
    resolved_at: Optional[datetime] = Field(None, description="解除時間")


# --- Dependencies ---


async def get_resource_monitor(request: Request) -> ResourceMonitor:
    """取得 ResourceMonitor 實例（FastAPI 依賴注入）.

    優先從 app.state 取得（lifespan 初始化的實例），
    若不存在則建立新實例（向後相容測試場景）。
    """
    if hasattr(request.app.state, "resource_monitor"):
        return request.app.state.resource_monitor
    db_pool = await get_db()
    return ResourceMonitor(db_pool=db_pool)


# --- Helpers ---


def _metrics_to_response(metrics: SystemMetricsDataclass) -> SystemMetricsResponse:
    """將 SystemMetrics dataclass 轉換為 Pydantic response."""
    return SystemMetricsResponse(
        host=metrics.host,
        cpu_percent=metrics.cpu_percent,
        memory_percent=metrics.memory_percent,
        memory_used_gb=metrics.memory_used_gb,
        memory_total_gb=metrics.memory_total_gb,
        disk_percent=metrics.disk_percent,
        disk_used_gb=metrics.disk_used_gb,
        disk_total_gb=metrics.disk_total_gb,
        timestamp=metrics.timestamp,
    )


def _alert_to_response(alert: AlertDataclass) -> AlertResponse:
    """將 Alert dataclass 轉換為 Pydantic response."""
    return AlertResponse(
        id=alert.id,
        level=alert.level,
        host=alert.host,
        metric_name=alert.metric_name,
        current_value=alert.current_value,
        threshold_value=alert.threshold_value,
        message=alert.message,
        triggered_at=alert.triggered_at,
        resolved_at=alert.resolved_at,
    )


# --- Metrics Endpoints (mounted at /metrics) ---


@router.get("/{host}", response_model=SystemMetricsResponse)
async def get_current_metrics(
    host: HostTarget,
    monitor: ResourceMonitor = Depends(get_resource_monitor),
) -> SystemMetricsResponse:
    """取得指定主機的當前系統指標.

    透過 ResourceMonitor.collect_metrics() 即時採集指標。
    """
    try:
        metrics = await monitor.collect_metrics(host)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))

    return _metrics_to_response(metrics)


@router.get("/{host}/history", response_model=list[SystemMetricsResponse])
async def get_metrics_history(
    host: HostTarget,
    hours: int = Query(default=24, ge=1, le=168, description="查詢時間範圍（小時）"),
    monitor: ResourceMonitor = Depends(get_resource_monitor),
) -> list[SystemMetricsResponse]:
    """查詢指定主機的歷史監控數據.

    透過 ResourceMonitor.query_history() 查詢資料庫中的歷史記錄。
    """
    end = datetime.utcnow()
    start = end - timedelta(hours=hours)

    try:
        history = await monitor.query_history(host, start, end)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))

    return [_metrics_to_response(m) for m in history]


# --- Alerts Endpoint (mounted at /alerts) ---


@alerts_router.get("", response_model=list[AlertResponse])
async def get_active_alerts(
    monitor: ResourceMonitor = Depends(get_resource_monitor),
) -> list[AlertResponse]:
    """取得當前活躍告警.

    對本地主機進行即時指標採集並評估閾值，回傳觸發的告警列表。
    """
    try:
        metrics = await monitor.collect_metrics(HostTarget.CORE)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))

    alerts = monitor.evaluate_thresholds(metrics)
    return [_alert_to_response(a) for a in alerts]
