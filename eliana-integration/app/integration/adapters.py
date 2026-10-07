"""子系統 Adapter — 將六個既有子系統包裝為 SubsystemProtocol。

每個 Adapter 實作標準生命週期（initialize/start/stop/health_check），並可
將子系統事件路由至 Event_Bus。真實子系統的呼叫透過注入的 backend 提供，
本機測試以 mock backend 驗證；RHEL VM 階段再接上真實子系統實例。
"""
from __future__ import annotations

from typing import Any

import structlog

from .event_bus import EventBus
from .models import HealthState, ModuleHealth

logger = structlog.get_logger(__name__)


class BaseAdapter:
    """SubsystemProtocol 的共用實作。

    backend 為選填的真實子系統物件；未提供時 adapter 以「就緒但無操作」模式運作
    （適合本機整合測試與模組獨立啟動）。
    """

    name: str = "base"

    def __init__(self, event_bus: EventBus, backend: Any | None = None) -> None:
        self._bus = event_bus
        self._backend = backend
        self._started = False
        self._initialized = False

    async def initialize(self) -> None:
        if self._backend is not None and hasattr(self._backend, "initialize"):
            await _maybe_await(self._backend.initialize())
        self._initialized = True

    async def start(self) -> None:
        if self._backend is not None and hasattr(self._backend, "start"):
            await _maybe_await(self._backend.start())
        self._started = True
        logger.info("subsystem_started", subsystem=self.name)

    async def stop(self) -> None:
        if self._backend is not None and hasattr(self._backend, "stop"):
            await _maybe_await(self._backend.stop())
        self._started = False
        logger.info("subsystem_stopped", subsystem=self.name)

    async def health_check(self) -> ModuleHealth:
        # 若 backend 提供 health_check 則委派，否則以啟動狀態回報
        if self._backend is not None and hasattr(self._backend, "health_check"):
            try:
                result = await _maybe_await(self._backend.health_check())
                if isinstance(result, ModuleHealth):
                    return result
                # 允許 backend 回 bool
                state = HealthState.HEALTHY if result else HealthState.UNHEALTHY
                return ModuleHealth(module=self.name, state=state)
            except Exception as exc:  # noqa: BLE001
                return ModuleHealth(module=self.name, state=HealthState.UNHEALTHY,
                                    error=str(exc))
        state = HealthState.HEALTHY if self._started else HealthState.DEGRADED
        return ModuleHealth(module=self.name, state=state,
                            error=None if self._started else "not started")


async def _maybe_await(value: Any) -> Any:
    import inspect
    if inspect.isawaitable(value):
        return await value
    return value


class CoreInfraAdapter(BaseAdapter):
    name = "core_infra"


class BountyHunterAdapter(BaseAdapter):
    name = "bounty_hunter"


class DigitalWalletAdapter(BaseAdapter):
    name = "digital_wallet"


class LearningEngineAdapter(BaseAdapter):
    name = "learning_engine"


class PersonalityAdapter(BaseAdapter):
    name = "personality"


class DashboardAdapter(BaseAdapter):
    name = "dashboard"


# 子系統名稱 → Adapter 類別
ADAPTER_CLASSES = {
    "core_infra": CoreInfraAdapter,
    "bounty_hunter": BountyHunterAdapter,
    "digital_wallet": DigitalWalletAdapter,
    "learning_engine": LearningEngineAdapter,
    "personality": PersonalityAdapter,
    "dashboard": DashboardAdapter,
}


def build_all_adapters(
    event_bus: EventBus,
    backends: dict[str, Any] | None = None,
) -> dict[str, BaseAdapter]:
    """建立全部六個子系統 adapter。backends 提供對應真實子系統物件（選填）。"""
    backends = backends or {}
    return {
        name: cls(event_bus, backends.get(name))
        for name, cls in ADAPTER_CLASSES.items()
    }
