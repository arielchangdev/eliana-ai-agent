"""Pydantic v2 資料模型。

所有欄位型別與 design.md 一致。含 severity 枚舉驗證與金額非負驗證。
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# --------------------------------------------------------------------------- #
# 設定模型
# --------------------------------------------------------------------------- #
class WalletConfig(BaseModel):
    electrum_servers: list[str]
    sync_interval_seconds: int = 300
    max_failover_attempts: int = 3
    wallet_path: Path


class KeyVaultConfig(BaseModel):
    encrypted_wallet_path: Path
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536  # 64 MB (KiB)
    argon2_parallelism: int = 4
    lockout_duration_minutes: int = 15
    max_failed_attempts: int = 3


class BackupConfig(BaseModel):
    backup_dir: Path
    max_backups: int = 30
    cron_expr: str = "0 3 * * *"


# --------------------------------------------------------------------------- #
# 交易與餘額模型
# --------------------------------------------------------------------------- #
class TransactionRecord(BaseModel):
    txid: str
    amount_btc: float = Field(ge=0.0)
    amount_sat: int = Field(ge=0)
    address: str
    confirmed_at: datetime
    platform: Optional[str] = None
    vuln_id: Optional[str] = None
    severity: Optional[str] = None
    note: Optional[str] = None

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        allowed = {s.value for s in Severity}
        if v not in allowed:
            raise ValueError(f"severity 必須為 {allowed} 之一，收到: {v}")
        return v


class WalletBalance(BaseModel):
    confirmed_btc: float = Field(ge=0.0)
    unconfirmed_btc: float = Field(ge=0.0)
    confirmed_sat: int = Field(ge=0)
    unconfirmed_sat: int = Field(ge=0)


class BalanceSummary(BaseModel):
    confirmed_btc: float = Field(ge=0.0)
    unconfirmed_btc: float = Field(ge=0.0)
    usd_value: float = Field(ge=0.0)
    rate_btc_usd: float = Field(ge=0.0)
    rate_updated_at: Optional[datetime] = None
    rate_is_cached: bool = False


class CumulativeStats(BaseModel):
    total_btc: float = Field(ge=0.0)
    transaction_count: int = Field(ge=0)
    average_btc: float = Field(ge=0.0)
    platform_breakdown: dict[str, float] = Field(default_factory=dict)


class MonthlyReport(BaseModel):
    year: int
    month: int
    transaction_count: int = Field(ge=0)
    total_btc: float = Field(ge=0.0)
    growth_rate: Optional[float] = None


class LedgerFilter(BaseModel):
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    platform: Optional[str] = None
    severity: Optional[str] = None


# --------------------------------------------------------------------------- #
# 備份模型
# --------------------------------------------------------------------------- #
class BackupMeta(BaseModel):
    backup_id: str
    created_at: datetime
    file_size_bytes: int = Field(ge=0)
    sha256_checksum: str
    backup_path: str


class BackupResult(BaseModel):
    success: bool
    backup_id: Optional[str] = None
    checksum: Optional[str] = None
    error: Optional[str] = None


class RestoreResult(BaseModel):
    success: bool
    records_restored: int = 0
    error: Optional[str] = None
