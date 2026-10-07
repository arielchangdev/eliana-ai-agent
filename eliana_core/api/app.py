"""FastAPI 應用程式實例與生命週期管理.

啟動時初始化所有核心服務（DB、SSH、監控、LLM），
關閉時優雅地清理所有資源。服務實例透過 app.state 提供依賴注入。
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from eliana_core.db.database import init_db, close_db
from eliana_core.services.ssh_channel import SSHChannel
from eliana_core.services.resource_monitor import ResourceMonitor
from eliana_core.services.task_scheduler import TaskSchedulerService
from eliana_core.services.local_llm import LocalLLM
from eliana_core.api.routes.tasks import router as tasks_router
from eliana_core.api.routes.metrics import router as metrics_router
from eliana_core.api.routes.metrics import alerts_router
from eliana_core.api.routes.llm import router as llm_router
from eliana_core.api.routes.health import router as health_router


logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """應用程式生命週期管理.

    啟動階段（Req 1.3: 自動啟動排程器與監控；Req 1.4: 建立 SSH 通道）：
    1. 初始化 SQLite 資料庫連線池
    2. 建立 SSHChannel 實例（不立即連線，等待設定就緒）
    3. 建立 TaskSchedulerService 實例
    4. 建立 ResourceMonitor 實例
    5. 建立 LocalLLM 實例
    6. 啟動 ResourceMonitor 背景監控循環（每 10 秒）

    關閉階段（優雅關閉）：
    1. 停止 ResourceMonitor 監控循環
    2. 關閉 SSH 連線
    3. 關閉 LocalLLM HTTP 客戶端
    4. 關閉資料庫連線池
    """
    # --- 啟動階段 ---
    logger.info("Eliana Core 啟動中：初始化服務...")

    # 1. 初始化資料庫
    db_pool = await init_db()
    logger.info("資料庫初始化完成")

    # 2. 建立 SSH 通道實例（尚未連線，設定可能未就緒）
    ssh_host = os.environ.get("ELIANA_SSH_HOST", "127.0.0.1")
    ssh_port = int(os.environ.get("ELIANA_SSH_PORT", "22"))
    ssh_username = os.environ.get("ELIANA_SSH_USERNAME", "root")
    ssh_key_path = os.environ.get("ELIANA_SSH_KEY_PATH", "~/.ssh/id_ed25519")

    ssh_channel = SSHChannel(
        host=ssh_host,
        port=ssh_port,
        username=ssh_username,
        private_key_path=ssh_key_path,
    )
    logger.info("SSH 通道已建立（host=%s, port=%d）", ssh_host, ssh_port)

    # 3. 建立 TaskSchedulerService 實例
    task_scheduler = TaskSchedulerService(db_pool=db_pool, ssh_channel=ssh_channel)
    logger.info("任務排程器已初始化")

    # 4. 建立 ResourceMonitor 實例
    resource_monitor = ResourceMonitor(ssh_channel=ssh_channel, db_pool=db_pool)
    logger.info("資源監控器已初始化")

    # 5. 建立 LocalLLM 實例
    ollama_url = os.environ.get("ELIANA_OLLAMA_URL", "http://localhost:11434")
    local_llm = LocalLLM(base_url=ollama_url)
    logger.info("本地 LLM 服務已初始化（url=%s）", ollama_url)

    # 6. 啟動背景監控循環（每 10 秒，Req 1.3）
    await resource_monitor.start_monitoring_loop()
    logger.info("背景監控循環已啟動")

    # 將服務實例存入 app.state 供路由依賴注入使用
    app.state.db_pool = db_pool
    app.state.ssh_channel = ssh_channel
    app.state.task_scheduler = task_scheduler
    app.state.resource_monitor = resource_monitor
    app.state.local_llm = local_llm

    logger.info("Eliana Core 啟動完成：所有服務已就緒")

    yield

    # --- 關閉階段（優雅關閉）---
    logger.info("Eliana Core 關閉中：清理資源...")

    # 1. 停止監控循環
    await resource_monitor.stop_monitoring_loop()
    logger.info("背景監控循環已停止")

    # 2. 關閉 SSH 連線
    await ssh_channel.close()
    logger.info("SSH 連線已關閉")

    # 3. 關閉 LLM HTTP 客戶端
    await local_llm.close()
    logger.info("LLM HTTP 客戶端已關閉")

    # 4. 關閉資料庫連線池
    await close_db()
    logger.info("資料庫連線池已關閉")

    logger.info("Eliana Core 已完全關閉")


app = FastAPI(
    title="Eliana Core API",
    description="Eliana 自主紅隊 AI Agent 核心基礎設施內部 API",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(tasks_router, prefix="/tasks", tags=["tasks"])
app.include_router(metrics_router, prefix="/metrics", tags=["metrics"])
app.include_router(alerts_router, prefix="/alerts", tags=["alerts"])
app.include_router(llm_router, prefix="/llm", tags=["llm"])
app.include_router(health_router, prefix="/health", tags=["health"])
