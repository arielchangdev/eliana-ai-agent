"""系統健康檢查 API 端點.

實作 GET /health 端點，回傳整體系統健康狀態。
"""

from datetime import datetime

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from eliana_core.db.database import get_db
from eliana_core.services.local_llm import LocalLLM


router = APIRouter()


# --- Pydantic Schemas ---


class ComponentHealth(BaseModel):
    """單一元件健康狀態."""

    name: str = Field(..., description="元件名稱")
    status: str = Field(..., description="健康狀態: healthy / unhealthy / degraded")
    message: str = Field(default="", description="額外描述訊息")


class HealthStatus(BaseModel):
    """系統整體健康狀態回應 schema."""

    status: str = Field(..., description="整體狀態: healthy / unhealthy / degraded")
    timestamp: datetime = Field(..., description="檢查時間")
    components: list[ComponentHealth] = Field(
        default_factory=list, description="各元件健康狀態"
    )


# --- Endpoints ---


@router.get("", response_model=HealthStatus)
async def health_check(request: Request) -> HealthStatus:
    """系統健康檢查.

    檢查資料庫、LLM 服務等元件的健康狀態，
    回傳整體系統健康資訊。
    """
    components: list[ComponentHealth] = []
    overall_status = "healthy"

    # 檢查資料庫連線
    db_health = await _check_db_health()
    components.append(db_health)
    if db_health.status == "unhealthy":
        overall_status = "unhealthy"
    elif db_health.status == "degraded" and overall_status == "healthy":
        overall_status = "degraded"

    # 檢查 LLM 服務
    llm_instance = None
    if hasattr(request.app.state, "local_llm"):
        llm_instance = request.app.state.local_llm
    llm_health = await _check_llm_health(llm_instance)
    components.append(llm_health)
    if llm_health.status == "unhealthy":
        if overall_status == "healthy":
            overall_status = "degraded"
    elif llm_health.status == "degraded" and overall_status == "healthy":
        overall_status = "degraded"

    # 檢查 SSH 連線
    ssh_channel = None
    if hasattr(request.app.state, "ssh_channel"):
        ssh_channel = request.app.state.ssh_channel
    ssh_health = _check_ssh_health(ssh_channel)
    components.append(ssh_health)
    if ssh_health.status == "unhealthy":
        if overall_status == "healthy":
            overall_status = "degraded"

    return HealthStatus(
        status=overall_status,
        timestamp=datetime.utcnow(),
        components=components,
    )


async def _check_db_health() -> ComponentHealth:
    """檢查資料庫連線狀態."""
    try:
        db_pool = await get_db()
        conn = await db_pool.get_connection()
        try:
            await conn.execute("SELECT 1")
        finally:
            await db_pool.release_connection(conn)
        return ComponentHealth(
            name="database",
            status="healthy",
            message="SQLite connection OK",
        )
    except Exception as e:
        return ComponentHealth(
            name="database",
            status="unhealthy",
            message=f"Database unavailable: {e}",
        )


async def _check_llm_health(llm: LocalLLM = None) -> ComponentHealth:
    """檢查 LLM 服務連線狀態."""
    try:
        if llm is None:
            llm = LocalLLM()
            models = await llm.get_loaded_models()
            await llm.close()
        else:
            models = await llm.get_loaded_models()
        return ComponentHealth(
            name="llm",
            status="healthy",
            message=f"Ollama running, {len(models)} model(s) available",
        )
    except Exception as e:
        return ComponentHealth(
            name="llm",
            status="unhealthy",
            message=f"LLM service unavailable: {e}",
        )


def _check_ssh_health(ssh_channel=None) -> ComponentHealth:
    """檢查 SSH 通道狀態."""
    if ssh_channel is None:
        return ComponentHealth(
            name="ssh",
            status="degraded",
            message="SSH channel not configured",
        )
    if ssh_channel.is_connected:
        return ComponentHealth(
            name="ssh",
            status="healthy",
            message="SSH connection active",
        )
    return ComponentHealth(
        name="ssh",
        status="degraded",
        message="SSH channel initialized but not connected",
    )
