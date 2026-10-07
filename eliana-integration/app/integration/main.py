"""Integration_App — 統一 FastAPI 應用程式。

連線六大元件（EventBus、PipelineOrchestrator、StartupValidator、LicenseScanner、
ConfigManager、HealthEndpoint）與六個子系統 adapter。提供 /health、/pipeline、
/config、/compliance 端點。支援整合啟動模式與模組獨立啟動模式。

以工廠函式 create_app(...) 建立，所有相依可注入以利測試（外部服務以 mock 提供）。
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from .adapters import build_all_adapters
from .config_manager import ConfigManager
from .event_bus import EventBus
from .exceptions import StartupValidationError
from .health_endpoint import HealthEndpoint
from .license_scanner import LicenseScanner
from .models import PipelineStage
from .pipeline import PipelineOrchestrator, StageHandler
from .startup_validator import StartupValidator

logger = structlog.get_logger(__name__)


class IntegrationApp:
    """整合應用的元件容器。"""

    def __init__(
        self,
        *,
        event_bus: EventBus | None = None,
        config_manager: ConfigManager | None = None,
        startup_validator: StartupValidator | None = None,
        license_scanner: LicenseScanner | None = None,
        pipeline_handlers: dict[PipelineStage, StageHandler] | None = None,
        backends: dict[str, Any] | None = None,
        bounty: Any | None = None,
        wallet: Any | None = None,
        learning: Any | None = None,
        skip_validation: bool = False,
        standalone: bool = False,
    ) -> None:
        self.event_bus = event_bus or EventBus()
        self.config_manager = config_manager or ConfigManager()
        self.startup_validator = startup_validator or StartupValidator(self.event_bus)
        self.license_scanner = license_scanner or LicenseScanner(self.event_bus)
        self.adapters = build_all_adapters(self.event_bus, backends)

        # 若未顯式提供 handlers，但注入了子系統埠口，則組裝真實 handlers。
        if pipeline_handlers is None and (bounty is not None or wallet is not None):
            from .subsystems import build_pipeline_handlers
            pipeline_handlers = build_pipeline_handlers(bounty=bounty, wallet=wallet)
        self.orchestrator = PipelineOrchestrator(self.event_bus, pipeline_handlers)

        # 策略回饋：把 pipeline 結果送進 learning engine
        if learning is not None:
            from .pipeline import TOPIC_STRATEGY_FEEDBACK
            from .subsystems import make_strategy_feedback_subscriber
            self.event_bus.subscribe(
                TOPIC_STRATEGY_FEEDBACK,
                make_strategy_feedback_subscriber(learning),
            )
        # HealthEndpoint 以各 adapter 的 health_check 為 provider
        self.health = HealthEndpoint({
            name: ad.health_check for name, ad in self.adapters.items()
        })
        self.skip_validation = skip_validation
        self.standalone = standalone
        self._bg_tasks: list[asyncio.Task] = []
        self.ready = False

    async def startup(self) -> None:
        await self.event_bus.start()
        # 模組獨立啟動模式跳過跨系統驗證
        if not self.standalone:
            try:
                await self.startup_validator.validate_all(
                    skip_validation=self.skip_validation)
            except StartupValidationError:
                await self.event_bus.stop()
                raise
        # 初始化並啟動所有子系統
        for ad in self.adapters.values():
            await ad.initialize()
            await ad.start()
        self.ready = True
        logger.info("integration_app_ready", standalone=self.standalone)

    async def shutdown(self) -> None:
        for ad in self.adapters.values():
            await ad.stop()
        for t in self._bg_tasks:
            t.cancel()
        await self.event_bus.stop()
        self.ready = False


def create_app(**kwargs: Any) -> FastAPI:
    """建立 FastAPI 應用。kwargs 轉給 IntegrationApp（供測試注入）。"""
    integration = IntegrationApp(**kwargs)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await integration.startup()
        try:
            yield
        finally:
            await integration.shutdown()

    app = FastAPI(title="Eliana Integration_App", version="0.1.0", lifespan=lifespan)
    app.state.integration = integration

    @app.get("/health")
    async def health():
        status = await integration.health.get_cached_health()
        code, body = integration.health.to_response(status)
        return JSONResponse(status_code=code, content=body)

    @app.post("/pipeline")
    async def start_pipeline(target: dict | None = None):
        run = await integration.orchestrator.start_pipeline(target or {})
        return {
            "pipeline_id": run.pipeline_id,
            "status": run.status.value,
            "failed_stage": run.failed_stage.value if run.failed_stage else None,
            "stages": [{"stage": s.stage.value, "status": s.status.value}
                       for s in run.stages],
        }

    @app.get("/pipeline/{pipeline_id}")
    async def pipeline_status(pipeline_id: str):
        run = integration.orchestrator.get_pipeline_status(pipeline_id)
        if run is None:
            raise HTTPException(status_code=404, detail="pipeline not found")
        return {
            "pipeline_id": run.pipeline_id,
            "status": run.status.value,
            "stages": [{"stage": s.stage.value, "status": s.status.value}
                       for s in run.stages],
        }

    @app.get("/config")
    async def get_config():
        return integration.config_manager.config

    @app.get("/compliance")
    async def compliance(packages: str | None = None):
        pkgs = packages.split(",") if packages else []
        results = await integration.license_scanner.scan_all(pkgs)
        import json
        return json.loads(LicenseScanner.generate_report(results))

    return app
