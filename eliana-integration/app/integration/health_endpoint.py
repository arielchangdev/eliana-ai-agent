"""Health_Endpoint — 系統健康檢查。

彙報所有子模組健康狀態，每 30 秒自動輪詢並快取結果。全部 healthy → HTTP 200；
任一 unhealthy → HTTP 503。子模組健康檢查超時視為 unhealthy。

各子模組的健康檢查以注入的 async provider 提供（回傳 ModuleHealth 或拋例外），
使外部子系統可 mock。
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Awaitable, Callable

import structlog

from .models import HealthState, HealthStatus, ModuleHealth

logger = structlog.get_logger(__name__)

# 健康檢查提供者：回傳 ModuleHealth
HealthProvider = Callable[[], Awaitable[ModuleHealth]]

CACHE_TTL_SECONDS = 30.0
CHECK_TIMEOUT_SECONDS = 5.0


class HealthEndpoint:
    """健康檢查彙總與快取。"""

    def __init__(
        self,
        providers: dict[str, HealthProvider] | None = None,
        *,
        cache_ttl: float = CACHE_TTL_SECONDS,
        check_timeout: float = CHECK_TIMEOUT_SECONDS,
    ) -> None:
        self._providers: dict[str, HealthProvider] = providers or {}
        self._cache_ttl = cache_ttl
        self._check_timeout = check_timeout
        self._cached: HealthStatus | None = None
        self._cached_at: float = 0.0

    def register_provider(self, module: str, provider: HealthProvider) -> None:
        self._providers[module] = provider

    async def _check_one(self, module: str, provider: HealthProvider) -> ModuleHealth:
        try:
            return await asyncio.wait_for(provider(), timeout=self._check_timeout)
        except asyncio.TimeoutError:
            return ModuleHealth(module=module, state=HealthState.UNHEALTHY,
                                error="health check timeout")
        except Exception as exc:  # noqa: BLE001
            return ModuleHealth(module=module, state=HealthState.UNHEALTHY,
                                error=str(exc))

    def _aggregate(self, modules: list[ModuleHealth]) -> HealthState:
        if any(m.state == HealthState.UNHEALTHY for m in modules):
            return HealthState.UNHEALTHY
        if any(m.state == HealthState.DEGRADED for m in modules):
            return HealthState.DEGRADED
        return HealthState.HEALTHY

    async def check_all(self) -> HealthStatus:
        """即時檢查所有子模組並更新快取。"""
        results = await asyncio.gather(*(
            self._check_one(name, prov) for name, prov in self._providers.items()
        ))
        modules = list(results)
        status = HealthStatus(
            overall=self._aggregate(modules),
            modules=modules,
            checked_at=datetime.now(timezone.utc),
        )
        self._cached = status
        self._cached_at = time.monotonic()
        return status

    async def get_cached_health(self) -> HealthStatus:
        """回傳快取結果；過期或無快取時觸發即時檢查。"""
        if self._cached is None or (time.monotonic() - self._cached_at) >= self._cache_ttl:
            return await self.check_all()
        return self._cached

    async def poll_loop(self) -> None:
        """背景輪詢（每 cache_ttl 秒）。由 main app 啟動。"""
        while True:
            try:
                await self.check_all()
            except Exception as exc:  # noqa: BLE001
                logger.warning("health_poll_error", error=str(exc))
            await asyncio.sleep(self._cache_ttl)

    def to_response(self, status: HealthStatus) -> tuple[int, dict]:
        """轉為 (http_status_code, json_body)。"""
        body = {
            "status": status.overall.value,
            "checked_at": status.checked_at.isoformat(),
            "modules": [
                {
                    "module": m.module,
                    "state": m.state.value,
                    "last_checked": m.last_checked.isoformat(),
                    "error": m.error,
                }
                for m in status.modules
            ],
        }
        return status.http_status, body
