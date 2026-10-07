"""應用程式啟動與生命週期管理。

build_components() 組裝所有服務；create_app() 建立可獨立運行的 FastAPI app
（含 WebSocket + REST 路由與 lifespan）。整合至 eliana-core-infra 時可改為
在其 app 上掛載 router。
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI

from .api.rest_routes import DashboardComponents, create_rest_router
from .api.websocket_routes import create_websocket_router
from .db.database import DatabaseManager
from .services.data_aggregator import DataAggregator
from .services.notification_engine import NotificationEngine
from .services.websocket_manager import WebSocketManager

logger = logging.getLogger(__name__)


async def build_components(
    db_path: str = "data/dashboard.db",
    telegram_send_fn=None,
    resource_provider=None,
    task_provider=None,
    knowledge_provider=None,
    agent_state_provider=None,
) -> DashboardComponents:
    """組裝並初始化所有服務。"""
    db = DatabaseManager(db_path)
    await db.initialize()

    aggregator = DataAggregator(
        resource_provider=resource_provider,
        task_provider=task_provider,
        knowledge_provider=knowledge_provider,
        agent_state_provider=agent_state_provider,
    )

    async def _default_sender(text: str) -> None:
        if telegram_send_fn is not None:
            await telegram_send_fn(text)

    notification_engine = NotificationEngine(sender=_default_sender)

    ws_manager = WebSocketManager(
        snapshot_provider=aggregator.get_full_snapshot
    )

    return DashboardComponents(
        aggregator=aggregator,
        notification_engine=notification_engine,
        ws_manager=ws_manager,
        db=db,
    )


def create_app(components: DashboardComponents) -> FastAPI:
    """建立獨立 FastAPI app，掛載 WebSocket + REST 路由。"""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # 啟動：啟動通知排程
        if components.notification_engine is not None:
            await components.notification_engine.start_scheduler()
            logger.info("通知排程已啟動")
        app.state.dashboard_components = components
        yield
        # 關閉：停止排程、關閉 DB
        if components.notification_engine is not None:
            await components.notification_engine.stop_scheduler()
        if components.db is not None:
            await components.db.close()
        logger.info("Dashboard 模組已關閉")

    app = FastAPI(
        title="Eliana Dashboard",
        description="Eliana 監控面板與行動通知 API",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(create_rest_router(components))
    if components.ws_manager is not None:
        app.include_router(create_websocket_router(components.ws_manager))
    return app
