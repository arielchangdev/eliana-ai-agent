"""SQLite 資料庫層。

以 stdlib ``sqlite3`` 為基礎，透過 ``asyncio.to_thread`` 提供 async 介面，
避免額外的第三方 async 驅動相依。所有寫入方法皆處理 weight 上下限
（0.01 ≤ weight ≤ 100.0）。
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .models import DetectionStrategy, StrategyStatus, TaskResult

WEIGHT_MIN = 0.01
WEIGHT_MAX = 100.0


def clamp_weight(weight: float) -> float:
    """將權重限制於 [WEIGHT_MIN, WEIGHT_MAX] 防止溢位。"""
    return max(WEIGHT_MIN, min(WEIGHT_MAX, weight))


_SCHEMA = """
CREATE TABLE IF NOT EXISTS crawl_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type TEXT NOT NULL,
    source_url TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('success','failed','rate_limited','skipped')),
    fragments_created INTEGER DEFAULT 0,
    error_message TEXT,
    duration_ms INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS strategy_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    strategy_id TEXT NOT NULL,
    previous_weight REAL NOT NULL,
    new_weight REAL NOT NULL,
    trigger_reason TEXT NOT NULL,
    success_rate REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS task_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL UNIQUE,
    strategy_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK(outcome IN ('success','failure','rejected')),
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS strategies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    vulnerability_types TEXT NOT NULL,
    tools TEXT NOT NULL,
    weight REAL DEFAULT 1.0 CHECK(weight > 0),
    status TEXT DEFAULT 'active',
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_crawl_logs_source ON crawl_logs(source_type, created_at);
CREATE INDEX IF NOT EXISTS idx_task_results_strategy ON task_results(strategy_id, created_at);
CREATE INDEX IF NOT EXISTS idx_strategy_history_id ON strategy_history(strategy_id, created_at);
"""


class SQLiteDB:
    """非同步 SQLite 封裝。

    使用單一持久連線（``check_same_thread=False``），所有讀寫呼叫皆包在
    ``asyncio.to_thread`` 內，並以鎖序列化，確保執行緒安全。
    傳入 ``":memory:"`` 可用於測試（in-memory）。
    """

    def __init__(self, db_path: str | Path = ":memory:"):
        self.db_path = str(db_path)
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = asyncio.Lock()

    # ----- 生命週期 ------------------------------------------------------- #
    async def initialize(self) -> None:
        """建立連線與資料表。"""
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        def _init() -> sqlite3.Connection:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.executescript(_SCHEMA)
            conn.commit()
            return conn

        self._conn = await asyncio.to_thread(_init)

    async def close(self) -> None:
        if self._conn is not None:
            conn = self._conn
            self._conn = None
            await asyncio.to_thread(conn.close)

    def _require_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("SQLiteDB 尚未初始化，請先呼叫 initialize()")
        return self._conn

    async def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        conn = self._require_conn()

        def _run() -> sqlite3.Cursor:
            cur = conn.execute(sql, params)
            conn.commit()
            return cur

        async with self._lock:
            return await asyncio.to_thread(_run)

    async def _query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        conn = self._require_conn()

        def _run() -> list[sqlite3.Row]:
            cur = conn.execute(sql, params)
            return cur.fetchall()

        async with self._lock:
            return await asyncio.to_thread(_run)

    # ----- crawl_logs ----------------------------------------------------- #
    async def insert_crawl_log(
        self,
        source_type: str,
        source_url: str,
        status: str,
        fragments_created: int = 0,
        error_message: Optional[str] = None,
        duration_ms: Optional[int] = None,
    ) -> None:
        await self._execute(
            """INSERT INTO crawl_logs
               (source_type, source_url, status, fragments_created, error_message, duration_ms)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (source_type, source_url, status, fragments_created, error_message, duration_ms),
        )

    async def get_crawl_logs(
        self,
        source_type: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM crawl_logs WHERE 1=1"
        params: list[Any] = []
        if source_type is not None:
            sql += " AND source_type = ?"
            params.append(source_type)
        if date_from is not None:
            sql += " AND created_at >= ?"
            params.append(date_from.isoformat(sep=" "))
        if date_to is not None:
            sql += " AND created_at <= ?"
            params.append(date_to.isoformat(sep=" "))
        sql += " ORDER BY created_at DESC"
        rows = await self._query(sql, tuple(params))
        return [dict(r) for r in rows]

    # ----- task_results --------------------------------------------------- #
    async def insert_task_result(self, result: TaskResult) -> None:
        await self._execute(
            """INSERT OR REPLACE INTO task_results
               (task_id, strategy_id, target_type, outcome, details)
               VALUES (?, ?, ?, ?, ?)""",
            (result.task_id, result.strategy_id, result.target_type,
             result.outcome, result.details),
        )

    async def get_recent_results_by_strategy(
        self, strategy_id: str, limit: int = 5
    ) -> list[dict[str, Any]]:
        rows = await self._query(
            """SELECT * FROM task_results
               WHERE strategy_id = ?
               ORDER BY created_at DESC, id DESC
               LIMIT ?""",
            (strategy_id, limit),
        )
        return [dict(r) for r in rows]

    async def get_task_result(self, task_id: str) -> Optional[dict[str, Any]]:
        rows = await self._query(
            "SELECT * FROM task_results WHERE task_id = ?", (task_id,)
        )
        return dict(rows[0]) if rows else None

    # ----- strategy_history ---------------------------------------------- #
    async def insert_strategy_history(
        self,
        strategy_id: str,
        previous_weight: float,
        new_weight: float,
        trigger_reason: str,
        success_rate: Optional[float] = None,
    ) -> None:
        await self._execute(
            """INSERT INTO strategy_history
               (strategy_id, previous_weight, new_weight, trigger_reason, success_rate)
               VALUES (?, ?, ?, ?, ?)""",
            (strategy_id, previous_weight, new_weight, trigger_reason, success_rate),
        )

    async def get_strategy_history(
        self,
        strategy_id: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM strategy_history WHERE 1=1"
        params: list[Any] = []
        if strategy_id is not None:
            sql += " AND strategy_id = ?"
            params.append(strategy_id)
        if date_from is not None:
            sql += " AND created_at >= ?"
            params.append(date_from.isoformat(sep=" "))
        if date_to is not None:
            sql += " AND created_at <= ?"
            params.append(date_to.isoformat(sep=" "))
        sql += " ORDER BY created_at DESC"
        rows = await self._query(sql, tuple(params))
        return [dict(r) for r in rows]

    # ----- strategies ----------------------------------------------------- #
    async def upsert_strategy(self, strategy: DetectionStrategy) -> None:
        weight = clamp_weight(strategy.weight)
        status = (
            strategy.status.value
            if isinstance(strategy.status, StrategyStatus)
            else str(strategy.status)
        )
        await self._execute(
            """INSERT INTO strategies
               (id, name, description, vulnerability_types, tools, weight, status,
                success_count, failure_count, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
               ON CONFLICT(id) DO UPDATE SET
                 name=excluded.name,
                 description=excluded.description,
                 vulnerability_types=excluded.vulnerability_types,
                 tools=excluded.tools,
                 weight=excluded.weight,
                 status=excluded.status,
                 success_count=excluded.success_count,
                 failure_count=excluded.failure_count,
                 updated_at=CURRENT_TIMESTAMP""",
            (
                strategy.id,
                strategy.name,
                strategy.description,
                json.dumps(strategy.vulnerability_types),
                json.dumps(strategy.tools),
                weight,
                status,
                strategy.success_count,
                strategy.failure_count,
            ),
        )

    async def update_strategy_weight(
        self, strategy_id: str, new_weight: float, new_status: str
    ) -> None:
        weight = clamp_weight(new_weight)
        await self._execute(
            """UPDATE strategies
               SET weight = ?, status = ?, updated_at = CURRENT_TIMESTAMP
               WHERE id = ?""",
            (weight, new_status, strategy_id),
        )

    async def get_strategy(self, strategy_id: str) -> Optional[DetectionStrategy]:
        rows = await self._query("SELECT * FROM strategies WHERE id = ?", (strategy_id,))
        return self._row_to_strategy(rows[0]) if rows else None

    async def get_all_strategies(self) -> list[DetectionStrategy]:
        rows = await self._query("SELECT * FROM strategies ORDER BY id")
        return [self._row_to_strategy(r) for r in rows]

    @staticmethod
    def _row_to_strategy(row: sqlite3.Row) -> DetectionStrategy:
        try:
            status = StrategyStatus(row["status"])
        except (ValueError, KeyError):
            status = StrategyStatus.ACTIVE
        return DetectionStrategy(
            id=row["id"],
            name=row["name"],
            description=row["description"] or "",
            vulnerability_types=json.loads(row["vulnerability_types"]),
            tools=json.loads(row["tools"]),
            weight=row["weight"],
            status=status,
            success_count=row["success_count"],
            failure_count=row["failure_count"],
        )
