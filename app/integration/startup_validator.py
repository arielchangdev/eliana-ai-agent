"""Startup_Validator — 系統啟動驗證器。

依序（並行）驗證：SSH 至 Weapon_Host、Ollama、Electrum daemon、ChromaDB、
Telegram Bot token。以 asyncio.gather 並行、asyncio.wait_for 設個別超時，
總時間限制 30 秒。任一關鍵依賴失敗即回報並阻止啟動；全部通過則發布
system_ready 事件。支援 --skip-validation 跳過。

各依賴的實際檢查以注入的 async check callable 提供（回傳 bool 或拋例外），
使外部服務（SSH/Ollama/Electrum/ChromaDB/Telegram）可 mock。
"""
from __future__ import annotations

import asyncio
import time
from typing import Awaitable, Callable

import structlog

from .event_bus import EventBus
from .exceptions import StartupValidationError
from .models import Event, ValidationResult

logger = structlog.get_logger(__name__)

# 檢查函式：回傳 True 表示通過，False 或拋例外表示失敗
CheckFn = Callable[[], Awaitable[bool]]

TOPIC_SYSTEM_READY = "system.ready"

DEFAULT_TOTAL_TIMEOUT = 30.0
DEFAULT_PER_CHECK_TIMEOUT = 10.0

# 關鍵依賴元件名稱
COMPONENTS = ["ssh", "ollama", "electrum", "chromadb", "telegram"]


class StartupValidator:
    """啟動驗證器。"""

    def __init__(
        self,
        event_bus: EventBus | None = None,
        checks: dict[str, CheckFn] | None = None,
        *,
        total_timeout: float = DEFAULT_TOTAL_TIMEOUT,
        per_check_timeout: float = DEFAULT_PER_CHECK_TIMEOUT,
    ) -> None:
        self._bus = event_bus
        self._checks: dict[str, CheckFn] = checks or {}
        self._total_timeout = total_timeout
        self._per_check_timeout = per_check_timeout
        self.last_results: list[ValidationResult] = []
        self.startup_duration_ms: float = 0.0

    def register_check(self, component: str, fn: CheckFn) -> None:
        self._checks[component] = fn

    async def _run_one(self, component: str) -> ValidationResult:
        fn = self._checks.get(component)
        start = time.perf_counter()
        if fn is None:
            # 未註冊檢查視為失敗（缺少關鍵依賴驗證）
            return ValidationResult(
                component=component, passed=False,
                error="no check registered",
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        try:
            ok = await asyncio.wait_for(fn(), timeout=self._per_check_timeout)
            return ValidationResult(
                component=component, passed=bool(ok),
                error=None if ok else "check returned False",
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        except asyncio.TimeoutError:
            return ValidationResult(
                component=component, passed=False, error="timeout",
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        except Exception as exc:  # noqa: BLE001
            return ValidationResult(
                component=component, passed=False, error=str(exc),
                duration_ms=(time.perf_counter() - start) * 1000,
            )

    # 個別驗證方法（薄包裝，方便單獨呼叫與測試）
    async def validate_ssh(self) -> ValidationResult:
        return await self._run_one("ssh")

    async def validate_ollama(self) -> ValidationResult:
        return await self._run_one("ollama")

    async def validate_electrum(self) -> ValidationResult:
        return await self._run_one("electrum")

    async def validate_chromadb(self) -> ValidationResult:
        return await self._run_one("chromadb")

    async def validate_telegram(self) -> ValidationResult:
        return await self._run_one("telegram")

    async def validate_all(self, *, skip_validation: bool = False) -> list[ValidationResult]:
        """並行執行所有驗證，回傳結果清單。

        skip_validation=True 時直接視為全部通過並發布 system_ready。
        任一關鍵依賴失敗時拋 StartupValidationError（阻止啟動）。
        """
        start = time.perf_counter()

        if skip_validation:
            self.last_results = [
                ValidationResult(component=c, passed=True, error="skipped")
                for c in COMPONENTS
            ]
            self.startup_duration_ms = (time.perf_counter() - start) * 1000
            await self._emit_ready()
            return self.last_results

        try:
            results = await asyncio.wait_for(
                asyncio.gather(*(self._run_one(c) for c in COMPONENTS)),
                timeout=self._total_timeout,
            )
        except asyncio.TimeoutError:
            self.startup_duration_ms = (time.perf_counter() - start) * 1000
            raise StartupValidationError(
                "startup validation exceeded total timeout",
                failed_components=["<timeout>"],
            )

        self.last_results = list(results)
        self.startup_duration_ms = (time.perf_counter() - start) * 1000

        failed = [r.component for r in results if not r.passed]
        if failed:
            logger.warning("startup_validation_failed", failed_components=failed)
            raise StartupValidationError(
                f"startup validation failed: {', '.join(failed)}",
                failed_components=failed,
            )

        await self._emit_ready()
        return self.last_results

    async def _emit_ready(self) -> None:
        if self._bus is not None:
            await self._bus.publish_and_wait(Event(
                topic=TOPIC_SYSTEM_READY,
                source="startup_validator",
                payload={"duration_ms": self.startup_duration_ms},
            ))
