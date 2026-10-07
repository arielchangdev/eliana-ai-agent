"""Eliana Core 應用程式入口模組.

提供 uvicorn 啟動函式與 CLI 入口點，
支援環境變數配置與日誌設定。
"""

import logging
import os
import sys

import uvicorn


def configure_logging(level: str = "INFO") -> None:
    """設定應用程式日誌格式與等級.

    Args:
        level: 日誌等級（DEBUG/INFO/WARNING/ERROR/CRITICAL）。
    """
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )


def run() -> None:
    """啟動 Eliana Core 應用程式.

    讀取環境變數配置並啟動 uvicorn 伺服器。

    環境變數：
        ELIANA_HOST: 監聽位址（預設 0.0.0.0）
        ELIANA_PORT: 監聽埠號（預設 8000）
        ELIANA_LOG_LEVEL: 日誌等級（預設 INFO）
        ELIANA_WORKERS: worker 數量（預設 1，SQLite 不宜多 worker）
    """
    host = os.environ.get("ELIANA_HOST", "0.0.0.0")
    port = int(os.environ.get("ELIANA_PORT", "8000"))
    log_level = os.environ.get("ELIANA_LOG_LEVEL", "INFO")
    workers = int(os.environ.get("ELIANA_WORKERS", "1"))

    configure_logging(log_level)

    logger = logging.getLogger(__name__)
    logger.info(
        "啟動 Eliana Core API: host=%s, port=%d, log_level=%s",
        host, port, log_level,
    )

    uvicorn.run(
        "eliana_core.api.app:app",
        host=host,
        port=port,
        log_level=log_level.lower(),
        workers=workers,
    )


if __name__ == "__main__":
    run()
