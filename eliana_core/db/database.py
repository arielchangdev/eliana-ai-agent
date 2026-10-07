"""資料庫初始化與連線管理模組.

使用 aiosqlite 實作非同步 SQLite 連線管理，
提供連線池模式與資料庫初始化功能。
"""

import asyncio
import logging
from pathlib import Path
from typing import Optional

import aiosqlite

logger = logging.getLogger(__name__)

# 預設資料庫路徑
DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "data" / "eliana.db"

# SQL Schema 定義
_SCHEMA_SQL = """
-- 任務表
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 2,
    category TEXT NOT NULL DEFAULT 'computation',
    status TEXT NOT NULL DEFAULT 'pending',
    dependencies TEXT DEFAULT '[]',
    payload TEXT DEFAULT '{}',
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_tasks_status_priority ON tasks(status, priority);

-- 系統指標表
CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    cpu_percent REAL NOT NULL,
    memory_percent REAL NOT NULL,
    memory_used_gb REAL NOT NULL,
    memory_total_gb REAL NOT NULL,
    disk_percent REAL NOT NULL,
    disk_used_gb REAL NOT NULL,
    disk_total_gb REAL NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_metrics_host_timestamp ON metrics(host, timestamp);

-- 告警表
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    level TEXT NOT NULL,
    host TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    current_value REAL NOT NULL,
    threshold_value REAL NOT NULL,
    message TEXT NOT NULL,
    triggered_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_level_resolved ON alerts(level, resolved_at);

-- SSH 連線記錄表
CREATE TABLE IF NOT EXISTS ssh_sessions (
    id TEXT PRIMARY KEY,
    connected_at TEXT NOT NULL,
    disconnected_at TEXT,
    key_rotated_at TEXT,
    status TEXT NOT NULL DEFAULT 'active'
);
"""


class DatabasePool:
    """非同步 SQLite 連線池.

    由於 SQLite 為單寫入者模型，此連線池管理多個讀取連線
    與一個寫入連線，透過信號量控制並行存取。
    """

    def __init__(self, db_path: Path, pool_size: int = 5) -> None:
        """初始化連線池.

        Args:
            db_path: SQLite 資料庫檔案路徑.
            pool_size: 連線池大小（最大並行連線數）.
        """
        self._db_path = db_path
        self._pool_size = pool_size
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._write_lock: Optional[asyncio.Lock] = None
        self._initialized = False

    @property
    def db_path(self) -> Path:
        """資料庫檔案路徑."""
        return self._db_path

    @property
    def initialized(self) -> bool:
        """連線池是否已初始化."""
        return self._initialized

    async def initialize(self) -> None:
        """初始化連線池，建立信號量與寫入鎖."""
        if self._initialized:
            return
        self._semaphore = asyncio.Semaphore(self._pool_size)
        self._write_lock = asyncio.Lock()
        self._initialized = True
        logger.info("資料庫連線池已初始化: %s (pool_size=%d)", self._db_path, self._pool_size)

    async def get_connection(self) -> aiosqlite.Connection:
        """從連線池取得一個連線.

        Returns:
            aiosqlite 連線物件.

        Raises:
            RuntimeError: 若連線池尚未初始化.
        """
        if not self._initialized or self._semaphore is None:
            raise RuntimeError("資料庫連線池尚未初始化，請先呼叫 initialize()")

        await self._semaphore.acquire()
        try:
            conn = await aiosqlite.connect(str(self._db_path))
            conn.row_factory = aiosqlite.Row
            await conn.execute("PRAGMA journal_mode=WAL")
            await conn.execute("PRAGMA foreign_keys=ON")
            return conn
        except Exception:
            self._semaphore.release()
            raise

    async def release_connection(self, conn: aiosqlite.Connection) -> None:
        """釋放連線回連線池.

        Args:
            conn: 要釋放的 aiosqlite 連線物件.
        """
        if self._semaphore is None:
            return
        try:
            await conn.close()
        finally:
            self._semaphore.release()

    async def execute_write(self, sql: str, params: tuple = ()) -> None:
        """執行寫入操作（序列化寫入）.

        Args:
            sql: SQL 語句.
            params: SQL 參數.
        """
        if self._write_lock is None:
            raise RuntimeError("資料庫連線池尚未初始化")

        async with self._write_lock:
            conn = await self.get_connection()
            try:
                await conn.execute(sql, params)
                await conn.commit()
            finally:
                await self.release_connection(conn)

    async def close(self) -> None:
        """關閉連線池."""
        self._initialized = False
        logger.info("資料庫連線池已關閉")


# 全域連線池實例
_pool: Optional[DatabasePool] = None


async def init_db(db_path: Optional[Path] = None, pool_size: int = 5) -> DatabasePool:
    """初始化資料庫：建立表格、索引與連線池.

    Args:
        db_path: 資料庫檔案路徑。若為 None 則使用預設路徑.
        pool_size: 連線池大小.

    Returns:
        已初始化的 DatabasePool 實例.
    """
    global _pool

    if db_path is None:
        db_path = DEFAULT_DB_PATH

    # 確保目錄存在
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # 建立連線池
    pool = DatabasePool(db_path, pool_size=pool_size)
    await pool.initialize()

    # 建立表格與索引
    conn = await pool.get_connection()
    try:
        await conn.executescript(_SCHEMA_SQL)
        await conn.commit()
        logger.info("資料庫結構已建立: %s", db_path)
    finally:
        await pool.release_connection(conn)

    _pool = pool
    return pool


async def get_db() -> DatabasePool:
    """取得全域資料庫連線池.

    Returns:
        DatabasePool 實例.

    Raises:
        RuntimeError: 若資料庫尚未初始化.
    """
    if _pool is None or not _pool.initialized:
        raise RuntimeError("資料庫尚未初始化，請先呼叫 init_db()")
    return _pool


async def close_db() -> None:
    """關閉全域資料庫連線池."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def reset_pool() -> None:
    """重置全域連線池（僅供測試使用）."""
    global _pool
    _pool = None
