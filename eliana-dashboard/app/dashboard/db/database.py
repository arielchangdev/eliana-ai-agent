"""SQLite 資料庫層（aiosqlite）。

管理 audit_logs、notifications、authorization_requests 三張表。
寫入失敗時最多重試 3 次。
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import aiosqlite

_MAX_RETRIES = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    user_id INTEGER,
    details TEXT NOT NULL DEFAULT '{}',
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_logs(event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_logs(user_id, timestamp);

CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    priority TEXT NOT NULL,
    event_type TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    link TEXT,
    created_at TEXT NOT NULL,
    sent_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_notifications_priority_sent ON notifications(priority, sent_at);

CREATE TABLE IF NOT EXISTS authorization_requests (
    request_id TEXT PRIMARY KEY,
    operation_description TEXT NOT NULL,
    target TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    decision TEXT,
    decided_at TEXT,
    decided_by INTEGER,
    telegram_message_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_requests_decision ON authorization_requests(decision, requested_at);
"""


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DatabaseManager:
    def __init__(self, db_path: str | Path = ":memory:"):
        self.db_path = str(db_path)
        self._conn: Optional[aiosqlite.Connection] = None

    async def initialize(self) -> None:
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(_SCHEMA)
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    def _require(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("DatabaseManager 尚未初始化，請先呼叫 initialize()")
        return self._conn

    async def _execute(self, sql: str, params: tuple = ()) -> None:
        conn = self._require()
        last_exc: Optional[Exception] = None
        for _ in range(_MAX_RETRIES):
            try:
                await conn.execute(sql, params)
                await conn.commit()
                return
            except aiosqlite.OperationalError as exc:
                last_exc = exc
                await asyncio.sleep(0.05)
        if last_exc:
            raise last_exc

    async def _query(self, sql: str, params: tuple = ()) -> list[aiosqlite.Row]:
        conn = self._require()
        async with conn.execute(sql, params) as cursor:
            return await cursor.fetchall()

    # ----- audit_logs ----------------------------------------------------- #
    async def insert_audit_log(
        self, log_id: str, event_type: str,
        user_id: Optional[int] = None, details: Optional[dict] = None,
    ) -> None:
        await self._execute(
            """INSERT INTO audit_logs (id, event_type, user_id, details, timestamp)
               VALUES (?, ?, ?, ?, ?)""",
            (log_id, event_type, user_id,
             json.dumps(details or {}), _utcnow_iso()),
        )

    async def get_audit_logs(
        self, event_type: Optional[str] = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        if event_type is not None:
            rows = await self._query(
                "SELECT * FROM audit_logs WHERE event_type = ? "
                "ORDER BY timestamp DESC LIMIT ?",
                (event_type, limit),
            )
        else:
            rows = await self._query(
                "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
        return [_row_with_details(r) for r in rows]

    # ----- notifications -------------------------------------------------- #
    async def insert_notification(
        self, notif_id: str, priority: str, event_type: str,
        title: str, summary: str, link: Optional[str] = None,
        created_at: Optional[str] = None, sent_at: Optional[str] = None,
    ) -> None:
        await self._execute(
            """INSERT INTO notifications
               (id, priority, event_type, title, summary, link, created_at, sent_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (notif_id, priority, event_type, title, summary, link,
             created_at or _utcnow_iso(), sent_at),
        )

    async def mark_notification_sent(self, notif_id: str) -> None:
        await self._execute(
            "UPDATE notifications SET sent_at = ? WHERE id = ?",
            (_utcnow_iso(), notif_id),
        )

    async def get_notifications(self, sent: Optional[bool] = None) -> list[dict]:
        if sent is True:
            rows = await self._query(
                "SELECT * FROM notifications WHERE sent_at IS NOT NULL "
                "ORDER BY created_at DESC"
            )
        elif sent is False:
            rows = await self._query(
                "SELECT * FROM notifications WHERE sent_at IS NULL "
                "ORDER BY created_at DESC"
            )
        else:
            rows = await self._query(
                "SELECT * FROM notifications ORDER BY created_at DESC"
            )
        return [dict(r) for r in rows]

    # ----- authorization_requests ---------------------------------------- #
    async def insert_authorization_request(
        self, request_id: str, operation_description: str, target: str,
        risk_level: str, requested_at: str, expires_at: str,
        telegram_message_id: Optional[str] = None,
    ) -> None:
        await self._execute(
            """INSERT INTO authorization_requests
               (request_id, operation_description, target, risk_level,
                requested_at, expires_at, telegram_message_id)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (request_id, operation_description, target, risk_level,
             requested_at, expires_at, telegram_message_id),
        )

    async def update_authorization_decision(
        self, request_id: str, decision: str, decided_by: Optional[int] = None,
    ) -> None:
        await self._execute(
            """UPDATE authorization_requests
               SET decision = ?, decided_at = ?, decided_by = ?
               WHERE request_id = ?""",
            (decision, _utcnow_iso(), decided_by, request_id),
        )

    async def get_authorization_request(self, request_id: str) -> Optional[dict]:
        rows = await self._query(
            "SELECT * FROM authorization_requests WHERE request_id = ?",
            (request_id,),
        )
        return dict(rows[0]) if rows else None


def _row_with_details(row: aiosqlite.Row) -> dict[str, Any]:
    d = dict(row)
    try:
        d["details"] = json.loads(d.get("details") or "{}")
    except (json.JSONDecodeError, TypeError):
        d["details"] = {}
    return d
