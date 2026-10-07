"""Transaction_Ledger：交易帳本（aiosqlite）。

交易記錄 CRUD、漏洞資訊關聯、修改歷史追蹤、篩選查詢、JSON 匯出、
從備份還原。重複 txid 以 UNIQUE 約束冪等處理。
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import aiosqlite

from ..models.schemas import LedgerFilter, TransactionRecord

_SCHEMA = """
CREATE TABLE IF NOT EXISTS transactions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    txid        TEXT NOT NULL UNIQUE,
    amount_btc  REAL NOT NULL,
    amount_sat  INTEGER NOT NULL,
    address     TEXT NOT NULL,
    confirmed_at TEXT NOT NULL,
    platform    TEXT,
    vuln_id     TEXT,
    severity    TEXT CHECK(severity IN ('critical','high','medium','low','info')),
    note        TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS transaction_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    txid        TEXT NOT NULL REFERENCES transactions(txid),
    field_name  TEXT NOT NULL,
    old_value   TEXT,
    new_value   TEXT,
    modified_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS backup_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    backup_id       TEXT NOT NULL UNIQUE,
    backup_path     TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    sha256_checksum TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_tx_confirmed ON transactions(confirmed_at);
CREATE INDEX IF NOT EXISTS idx_tx_platform ON transactions(platform);
CREATE INDEX IF NOT EXISTS idx_tx_severity ON transactions(severity);
CREATE INDEX IF NOT EXISTS idx_hist_txid ON transaction_history(txid);
"""

# 允許透過 update_field 修改的欄位（白名單，防止 SQL 注入）
_UPDATABLE_FIELDS = {"platform", "vuln_id", "severity", "note", "address",
                     "amount_btc", "amount_sat", "confirmed_at"}


class TransactionLedger:
    def __init__(self, db_path: str | Path = ":memory:"):
        self.db_path = str(db_path)
        self._conn: Optional[aiosqlite.Connection] = None

    async def initialize(self) -> None:
        """建立連線與 schema。"""
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

    def _require_conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("TransactionLedger 尚未初始化，請先呼叫 initialize()")
        return self._conn

    # ----- 記錄與查詢 ----------------------------------------------------- #
    async def record_transaction(self, tx: TransactionRecord) -> str:
        """插入交易記錄；重複 txid 冪等（忽略）。回傳 txid。"""
        conn = self._require_conn()
        await conn.execute(
            """INSERT OR IGNORE INTO transactions
               (txid, amount_btc, amount_sat, address, confirmed_at,
                platform, vuln_id, severity, note)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                tx.txid, tx.amount_btc, tx.amount_sat, tx.address,
                tx.confirmed_at.isoformat(), tx.platform, tx.vuln_id,
                tx.severity, tx.note,
            ),
        )
        await conn.commit()
        return tx.txid

    async def get_transaction(self, txid: str) -> Optional[TransactionRecord]:
        conn = self._require_conn()
        async with conn.execute(
            "SELECT * FROM transactions WHERE txid = ?", (txid,)
        ) as cursor:
            row = await cursor.fetchone()
        return self._row_to_record(row) if row else None

    async def query(self, filters: LedgerFilter) -> list[TransactionRecord]:
        """依 LedgerFilter 篩選（時間範圍、平台、嚴重等級）。"""
        conn = self._require_conn()
        sql = "SELECT * FROM transactions WHERE 1=1"
        params: list[Any] = []
        if filters.start_date is not None:
            sql += " AND confirmed_at >= ?"
            params.append(filters.start_date.isoformat())
        if filters.end_date is not None:
            sql += " AND confirmed_at <= ?"
            params.append(filters.end_date.isoformat())
        if filters.platform is not None:
            sql += " AND platform = ?"
            params.append(filters.platform)
        if filters.severity is not None:
            sql += " AND severity = ?"
            params.append(filters.severity)
        sql += " ORDER BY confirmed_at ASC"
        async with conn.execute(sql, tuple(params)) as cursor:
            rows = await cursor.fetchall()
        return [self._row_to_record(r) for r in rows]

    async def get_all(self) -> list[TransactionRecord]:
        return await self.query(LedgerFilter())

    async def export_json(self) -> str:
        """匯出所有記錄為結構化 JSON。"""
        records = await self.get_all()
        return json.dumps(
            [json.loads(r.model_dump_json()) for r in records],
            ensure_ascii=False, indent=2,
        )

    # ----- 漏洞關聯與修改歷史 --------------------------------------------- #
    async def link_bounty_info(
        self, txid: str, vuln_id: str, platform: str, severity: str
    ) -> None:
        """關聯漏洞資訊至交易，並記錄修改歷史。"""
        await self.update_field(txid, "vuln_id", vuln_id)
        await self.update_field(txid, "platform", platform)
        await self.update_field(txid, "severity", severity)

    async def update_field(self, txid: str, field: str, new_value: Any) -> None:
        """更新欄位並寫入 transaction_history（含 old_value、new_value）。"""
        if field not in _UPDATABLE_FIELDS:
            raise ValueError(f"不允許更新的欄位: {field}")
        conn = self._require_conn()

        # 取得舊值
        async with conn.execute(
            f"SELECT {field} FROM transactions WHERE txid = ?", (txid,)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            raise ValueError(f"交易不存在: {txid}")
        old_value = row[0]

        # 更新欄位 + updated_at
        await conn.execute(
            f"UPDATE transactions SET {field} = ?, updated_at = datetime('now') "
            f"WHERE txid = ?",
            (new_value, txid),
        )
        # 寫入修改歷史
        await conn.execute(
            """INSERT INTO transaction_history (txid, field_name, old_value, new_value)
               VALUES (?, ?, ?, ?)""",
            (txid, field,
             str(old_value) if old_value is not None else None,
             str(new_value) if new_value is not None else None),
        )
        await conn.commit()

    async def get_history(self, txid: str) -> list[dict[str, Any]]:
        conn = self._require_conn()
        async with conn.execute(
            "SELECT * FROM transaction_history WHERE txid = ? ORDER BY id ASC",
            (txid,),
        ) as cursor:
            rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def restore_from_backup(self, backup_db_path: str | Path) -> int:
        """從備份 SQLite 檔還原交易記錄，回傳還原筆數。"""
        src = aiosqlite.connect(str(backup_db_path))
        conn = self._require_conn()
        count = 0
        async with src as backup_conn:
            backup_conn.row_factory = aiosqlite.Row
            async with backup_conn.execute("SELECT * FROM transactions") as cursor:
                rows = await cursor.fetchall()
            for row in rows:
                await conn.execute(
                    """INSERT OR IGNORE INTO transactions
                       (txid, amount_btc, amount_sat, address, confirmed_at,
                        platform, vuln_id, severity, note)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (row["txid"], row["amount_btc"], row["amount_sat"],
                     row["address"], row["confirmed_at"], row["platform"],
                     row["vuln_id"], row["severity"], row["note"]),
                )
                count += 1
            await conn.commit()
        return count

    # ----- helper --------------------------------------------------------- #
    @staticmethod
    def _row_to_record(row: aiosqlite.Row) -> TransactionRecord:
        return TransactionRecord(
            txid=row["txid"],
            amount_btc=row["amount_btc"],
            amount_sat=row["amount_sat"],
            address=row["address"],
            confirmed_at=datetime.fromisoformat(row["confirmed_at"]),
            platform=row["platform"],
            vuln_id=row["vuln_id"],
            severity=row["severity"],
            note=row["note"],
        )
