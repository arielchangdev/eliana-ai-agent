"""Bounty 模組 SQLite 資料庫初始化與連線管理。

提供非同步資料庫初始化函式，建立所有必要資料表與索引，
並啟用 WAL 模式以提升並行讀取效能。
"""

from pathlib import Path

import aiosqlite

# SQL schema 定義
_SCHEMA_SQL = """
-- Bounty 計畫表
CREATE TABLE IF NOT EXISTS bounty_programs (
    id TEXT PRIMARY KEY,
    platform TEXT NOT NULL,
    platform_program_id TEXT NOT NULL,
    name TEXT NOT NULL,
    organization TEXT DEFAULT '',
    domains TEXT DEFAULT '[]',
    scope_in TEXT DEFAULT '[]',
    scope_out TEXT DEFAULT '[]',
    allowed_test_types TEXT DEFAULT '[]',
    bounty_range_low REAL DEFAULT 0.0,
    bounty_range_high REAL DEFAULT 0.0,
    trust_score REAL DEFAULT 0.0,
    trust_level TEXT DEFAULT 'suspicious',
    active_since TEXT,
    public_reports_count INTEGER DEFAULT 0,
    has_legal_terms INTEGER DEFAULT 0,
    whois_verified INTEGER DEFAULT 0,
    crawled_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_programs_platform ON bounty_programs(platform);
CREATE INDEX IF NOT EXISTS idx_programs_trust ON bounty_programs(trust_score);

-- 掃描記錄表
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES bounty_programs(id),
    target_url TEXT NOT NULL,
    target_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    profile TEXT DEFAULT '{}',
    started_at TEXT,
    completed_at TEXT,
    duration_seconds REAL DEFAULT 0.0
);

CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_program ON scans(program_id);

-- 漏洞發現表
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id),
    cve_id TEXT,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    affected_endpoint TEXT NOT NULL,
    evidence TEXT DEFAULT '',
    tool_source TEXT NOT NULL,
    raw_output TEXT DEFAULT '',
    discovered_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);

-- 授權記錄表
CREATE TABLE IF NOT EXISTS authorizations (
    id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL,
    program_id TEXT NOT NULL,
    target_url TEXT NOT NULL,
    scan_types TEXT DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending',
    requested_at TEXT NOT NULL,
    decided_at TEXT,
    expires_at TEXT,
    is_batch INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_auth_status ON authorizations(status);
CREATE INDEX IF NOT EXISTS idx_auth_program ON authorizations(program_id);

-- 報告表
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id),
    program_id TEXT NOT NULL REFERENCES bounty_programs(id),
    platform TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    reproduction_steps TEXT DEFAULT '',
    impact_assessment TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    cvss_score REAL DEFAULT 0.0,
    cvss_vector TEXT DEFAULT '',
    estimated_bounty_min REAL DEFAULT 0.0,
    estimated_bounty_max REAL DEFAULT 0.0,
    status TEXT NOT NULL DEFAULT 'draft',
    llm_quality_score REAL DEFAULT 0.0,
    generated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);

-- 變更事件表
CREATE TABLE IF NOT EXISTS change_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id TEXT NOT NULL,
    change_type TEXT NOT NULL,
    details TEXT DEFAULT '',
    detected_at TEXT NOT NULL
);

-- 掃描進度表（ScanEngine._progress_reporter 以 scan_id 為鍵即時更新）
CREATE TABLE IF NOT EXISTS scan_progress (
    scan_id TEXT PRIMARY KEY REFERENCES scans(id),
    percent_complete REAL DEFAULT 0.0,
    vulnerabilities_found INTEGER DEFAULT 0,
    estimated_remaining_seconds REAL DEFAULT 0.0,
    current_tool TEXT,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_progress_scan ON scan_progress(scan_id);
"""


async def init_bounty_db(db_path: str = "data/bounty.db") -> aiosqlite.Connection:
    """初始化 Bounty 模組的 SQLite 資料庫。

    建立所有資料表與索引，啟用 WAL 模式。若資料庫檔案或父目錄不存在，會自動建立。

    Args:
        db_path: 資料庫檔案路徑，預設為 "data/bounty.db"。
                 傳入 ":memory:" 可建立記憶體資料庫（用於測試）。

    Returns:
        已初始化的 aiosqlite 連線物件。
    """
    # 建立父目錄（僅在非記憶體資料庫時）
    if db_path != ":memory:":
        parent_dir = Path(db_path).parent
        parent_dir.mkdir(parents=True, exist_ok=True)

    db = await aiosqlite.connect(db_path)

    # 啟用 WAL 模式以提升並行讀取效能
    await db.execute("PRAGMA journal_mode=WAL")

    # 啟用外鍵約束
    await db.execute("PRAGMA foreign_keys=ON")

    # 執行所有 CREATE TABLE / CREATE INDEX 語句
    await db.executescript(_SCHEMA_SQL)
    await db.commit()

    return db


async def get_bounty_db(db_path: str = "data/bounty.db") -> aiosqlite.Connection:
    """取得已初始化的 Bounty 資料庫連線。

    若資料庫尚未初始化，會自動執行初始化流程。
    此為便利函式，每次呼叫都會建立新連線並確保 schema 存在。

    Args:
        db_path: 資料庫檔案路徑，預設為 "data/bounty.db"。

    Returns:
        已初始化的 aiosqlite 連線物件。
    """
    return await init_bounty_db(db_path)
