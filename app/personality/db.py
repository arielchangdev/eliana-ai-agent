"""SQLite 資料庫層（aiosqlite, WAL mode）。

管理五張表：personality_versions、evolution_log、rejection_cooldowns、
cumulative_changes、community_interactions。SQLite 鎖定時最多重試 3 次。
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import aiosqlite

_MAX_RETRIES = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS personality_versions (
    id TEXT PRIMARY KEY,
    version_number INTEGER NOT NULL UNIQUE,
    profile_snapshot TEXT NOT NULL,
    change_summary TEXT NOT NULL,
    created_at TEXT NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('manual','evolution','rollback','import'))
);
CREATE INDEX IF NOT EXISTS idx_versions_created ON personality_versions(created_at DESC);

CREATE TABLE IF NOT EXISTS evolution_log (
    id TEXT PRIMARY KEY,
    suggestion_id TEXT NOT NULL,
    parameter_path TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    change_percent REAL NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('applied','rejected','pending')),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evo_status ON evolution_log(status);

CREATE TABLE IF NOT EXISTS rejection_cooldowns (
    id TEXT PRIMARY KEY,
    parameter_path TEXT NOT NULL,
    direction TEXT NOT NULL CHECK(direction IN ('increase','decrease')),
    remaining_conversations INTEGER NOT NULL DEFAULT 30,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cumulative_changes (
    parameter_path TEXT PRIMARY KEY,
    cumulative_percent REAL NOT NULL DEFAULT 0.0,
    last_reset_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS community_interactions (
    id TEXT PRIMARY KEY,
    platform TEXT NOT NULL,
    interaction_type TEXT NOT NULL CHECK(interaction_type IN ('post','reply')),
    content_preview TEXT,
    authorized_by TEXT,
    published_at TEXT,
    rejected_reason TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_community_daily ON community_interactions(platform, created_at);
"""


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EvolutionDB:
    def __init__(self, db_path: str | Path = ":memory:"):
        self.db_path = str(db_path)
        self._conn: Optional[aiosqlite.Connection] = None

    async def init_schema(self) -> None:
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        # WAL mode（記憶體模式不支援，忽略錯誤）
        try:
            await self._conn.execute("PRAGMA journal_mode=WAL")
        except Exception:  # noqa: BLE001
            pass
        await self._conn.executescript(_SCHEMA)
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    def _require(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("EvolutionDB 尚未初始化，請先呼叫 init_schema()")
        return self._conn

    async def _execute(self, sql: str, params: tuple = ()) -> None:
        conn = self._require()
        last_exc: Optional[Exception] = None
        for _ in range(_MAX_RETRIES):
            try:
                await conn.execute(sql, params)
                await conn.commit()
                return
            except aiosqlite.OperationalError as exc:  # 鎖定重試
                last_exc = exc
                await asyncio.sleep(0.05)
        if last_exc:
            raise last_exc

    async def _query(self, sql: str, params: tuple = ()) -> list[aiosqlite.Row]:
        conn = self._require()
        async with conn.execute(sql, params) as cursor:
            return await cursor.fetchall()

    # ----- personality_versions ------------------------------------------ #
    async def insert_version(
        self, version_id: str, version_number: int, profile_snapshot: str,
        change_summary: str, source: str,
    ) -> None:
        await self._execute(
            """INSERT INTO personality_versions
               (id, version_number, profile_snapshot, change_summary, created_at, source)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (version_id, version_number, profile_snapshot, change_summary,
             _utcnow_iso(), source),
        )
        await self._prune_versions()

    async def _prune_versions(self, keep: int = 100) -> int:
        """FIFO：僅保留最近 keep 個版本。回傳刪除數。"""
        rows = await self._query(
            "SELECT id FROM personality_versions "
            "ORDER BY version_number DESC LIMIT -1 OFFSET ?",
            (keep,),
        )
        removed = 0
        for row in rows:
            await self._execute(
                "DELETE FROM personality_versions WHERE id = ?", (row["id"],)
            )
            removed += 1
        return removed

    async def get_versions(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = await self._query(
            "SELECT * FROM personality_versions "
            "ORDER BY version_number DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in rows]

    async def get_version(self, version_id: str) -> Optional[dict[str, Any]]:
        rows = await self._query(
            "SELECT * FROM personality_versions WHERE id = ?", (version_id,)
        )
        return dict(rows[0]) if rows else None

    async def get_max_version_number(self) -> int:
        rows = await self._query(
            "SELECT MAX(version_number) AS mx FROM personality_versions"
        )
        mx = rows[0]["mx"] if rows else None
        return int(mx) if mx is not None else 0

    # ----- evolution_log -------------------------------------------------- #
    async def insert_evolution_log(
        self, log_id: str, suggestion_id: str, parameter_path: str,
        old_value: str, new_value: str, change_percent: float, status: str,
    ) -> None:
        await self._execute(
            """INSERT INTO evolution_log
               (id, suggestion_id, parameter_path, old_value, new_value,
                change_percent, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (log_id, suggestion_id, parameter_path, old_value, new_value,
             change_percent, status, _utcnow_iso()),
        )

    async def get_evolution_logs(
        self, status: Optional[str] = None
    ) -> list[dict[str, Any]]:
        if status is not None:
            rows = await self._query(
                "SELECT * FROM evolution_log WHERE status = ? ORDER BY created_at",
                (status,),
            )
        else:
            rows = await self._query(
                "SELECT * FROM evolution_log ORDER BY created_at"
            )
        return [dict(r) for r in rows]

    async def update_log_status(self, suggestion_id: str, status: str) -> None:
        await self._execute(
            "UPDATE evolution_log SET status = ? WHERE suggestion_id = ?",
            (status, suggestion_id),
        )

    # ----- cumulative_changes -------------------------------------------- #
    async def get_cumulative(self, parameter_path: str) -> float:
        rows = await self._query(
            "SELECT cumulative_percent FROM cumulative_changes WHERE parameter_path = ?",
            (parameter_path,),
        )
        return float(rows[0]["cumulative_percent"]) if rows else 0.0

    async def update_cumulative(
        self, parameter_path: str, cumulative_percent: float
    ) -> None:
        await self._execute(
            """INSERT INTO cumulative_changes (parameter_path, cumulative_percent, last_reset_at)
               VALUES (?, ?, ?)
               ON CONFLICT(parameter_path) DO UPDATE SET
                 cumulative_percent = excluded.cumulative_percent""",
            (parameter_path, cumulative_percent, _utcnow_iso()),
        )

    async def reset_cumulative(self, parameter_path: str) -> None:
        await self._execute(
            """INSERT INTO cumulative_changes (parameter_path, cumulative_percent, last_reset_at)
               VALUES (?, 0.0, ?)
               ON CONFLICT(parameter_path) DO UPDATE SET
                 cumulative_percent = 0.0, last_reset_at = excluded.last_reset_at""",
            (parameter_path, _utcnow_iso()),
        )

    # ----- rejection_cooldowns ------------------------------------------- #
    async def insert_cooldown(
        self, cooldown_id: str, parameter_path: str, direction: str,
        remaining: int = 30,
    ) -> None:
        await self._execute(
            """INSERT INTO rejection_cooldowns
               (id, parameter_path, direction, remaining_conversations, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (cooldown_id, parameter_path, direction, remaining, _utcnow_iso()),
        )

    async def get_active_cooldowns(self) -> list[dict[str, Any]]:
        rows = await self._query(
            "SELECT * FROM rejection_cooldowns WHERE remaining_conversations > 0"
        )
        return [dict(r) for r in rows]

    async def decrement_cooldowns(self) -> None:
        """遞減所有冷卻計數，歸零者刪除。"""
        await self._execute(
            "UPDATE rejection_cooldowns "
            "SET remaining_conversations = remaining_conversations - 1 "
            "WHERE remaining_conversations > 0"
        )
        await self._execute(
            "DELETE FROM rejection_cooldowns WHERE remaining_conversations <= 0"
        )

    # ----- community_interactions ---------------------------------------- #
    async def insert_interaction(
        self, interaction_id: str, platform: str, interaction_type: str,
        content_preview: str = "", authorized_by: Optional[str] = None,
        published_at: Optional[str] = None, rejected_reason: Optional[str] = None,
    ) -> None:
        await self._execute(
            """INSERT INTO community_interactions
               (id, platform, interaction_type, content_preview, authorized_by,
                published_at, rejected_reason, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (interaction_id, platform, interaction_type, content_preview,
             authorized_by, published_at, rejected_reason, _utcnow_iso()),
        )

    async def get_daily_interaction_count(
        self, platform: str, day: Optional[str] = None
    ) -> int:
        """計算指定平台當日已「發送成功」的互動次數（published_at 非空）。"""
        target_day = day or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        rows = await self._query(
            "SELECT COUNT(*) AS cnt FROM community_interactions "
            "WHERE platform = ? AND published_at IS NOT NULL "
            "AND substr(created_at, 1, 10) = ?",
            (platform, target_day),
        )
        return int(rows[0]["cnt"]) if rows else 0
