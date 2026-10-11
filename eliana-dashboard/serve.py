"""Eliana Dashboard 啟動入口。

階段分段：
  * MODE=mock  : 用 adapters.py 的 Mock provider 驗證鏈路（不需真實 core）
  * MODE=real  : 用真實 ResourceMonitor adapter + 10s 背景輪詢（之後啟用）

serve 靜態前端 dist/（若存在），SPA fallback 到 index.html。
綁定位址/埠由環境變數控制，預設僅本機（安全預設）。
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

import uvicorn
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.dashboard.main import build_components, create_app
from app.dashboard.services.adapters import (
    MockResourceMonitor,
    MockTaskScheduler,
    MockKnowledgeStats,
)

MODE = os.environ.get("ELIANA_DASH__MODE", "mock")
HOST = os.environ.get("ELIANA_DASH__HOST", "127.0.0.1")
PORT = int(os.environ.get("ELIANA_DASH__PORT", "8000"))
DB_PATH = os.environ.get("ELIANA_DASH__DB", "data/dashboard.db")
DIST_DIR = os.environ.get(
    "ELIANA_DASH__DIST",
    str(Path(__file__).parent / "frontend" / "dist"),
)


async def _build_mock():
    """Mock 鏈路：provider 皆為無參 callable；resource 以 push 餵入。"""
    mock_rm = MockResourceMonitor()
    mock_task = MockTaskScheduler()
    mock_know = MockKnowledgeStats()

    components = await build_components(
        db_path=DB_PATH,
        resource_provider=mock_rm.get_metrics,          # callable
        task_provider=mock_task.get_recent_tasks,       # callable
        knowledge_provider=mock_know.get_stats,         # callable
        agent_state_provider=mock_task.get_agent_status,  # callable
    )
    # resources 走 push：啟動時先把 Mock 指標推入快取，snapshot 才非空
    for m in await mock_rm.get_metrics():
        components.aggregator.update_metrics(m)
    return components


def _attach_static(app) -> None:
    """若 dist/ 存在則掛載靜態前端，並設 SPA fallback。"""
    dist = Path(DIST_DIR)
    index = dist / "index.html"
    if not index.exists():
        return  # 尚未 build，純 API 模式

    assets = dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

    @app.get("/")
    async def _index():
        return FileResponse(str(index))

    # SPA fallback：非 /api /ws /assets 的路徑都回 index.html
    @app.get("/{full_path:path}")
    async def _spa(full_path: str):
        if full_path.startswith(("api/", "ws/", "assets/")):
            return FileResponse(str(index), status_code=404)
        candidate = dist / full_path
        if candidate.is_file():
            return FileResponse(str(candidate))
        return FileResponse(str(index))


async def _make_app():
    """建立 app，回傳 (app, poller)。poller 由啟動流程在同一 loop 內啟停，
    不走 on_event / lifespan 疊加（create_app 已佔用 lifespan，兩者不可並存）。"""
    poller = None
    if MODE == "mock":
        components = await _build_mock()
    else:
        from real_adapter import build_real_components
        components, poller = await build_real_components(db_path=DB_PATH)

    app = create_app(components)
    _attach_static(app)
    return app, poller


async def _serve() -> None:
    app, poller = await _make_app()
    # poller 在 uvicorn 的同一事件迴圈內啟動，確保資料持續 push 進 aggregator
    if poller is not None:
        await poller.start()
    config = uvicorn.Config(app, host=HOST, port=PORT, log_level="info")
    server = uvicorn.Server(config)
    try:
        await server.serve()
    finally:
        if poller is not None:
            await poller.stop()


def main() -> int:
    asyncio.run(_serve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
