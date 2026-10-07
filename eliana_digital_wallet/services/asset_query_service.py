"""Asset_Query_Service：資產查詢、匯率換算、統計與月報表。

- get_balance_summary：BTC 餘額 + CoinGecko USD 即時估值（失敗用快取）
- query_transactions：委託 TransactionLedger.query
- get_cumulative_stats：總收入、筆數、平均、各平台佔比
- generate_monthly_report：按月彙總 + 月對月成長率
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import httpx

from ..models.schemas import (
    BalanceSummary,
    CumulativeStats,
    LedgerFilter,
    MonthlyReport,
    TransactionRecord,
)
from .transaction_ledger import TransactionLedger
from .wallet_manager import WalletManager

_COINGECKO_URL = (
    "https://api.coingecko.com/api/v3/simple/price"
    "?ids=bitcoin&vs_currencies=usd"
)


class AssetQueryService:
    def __init__(
        self,
        wallet: WalletManager,
        ledger: TransactionLedger,
        http_client: Optional[httpx.AsyncClient] = None,
        rate_url: str = _COINGECKO_URL,
    ):
        self.wallet = wallet
        self.ledger = ledger
        self._http_client = http_client
        self._rate_url = rate_url
        # 匯率快取
        self._cached_rate: Optional[float] = None
        self._cached_rate_at: Optional[datetime] = None

    # ----- 餘額與匯率 ----------------------------------------------------- #
    async def get_balance_summary(self) -> BalanceSummary:
        balance = await self.wallet.get_balance()
        rate, updated_at, is_cached = await self._fetch_btc_usd_rate()
        usd_value = balance.confirmed_btc * rate
        return BalanceSummary(
            confirmed_btc=balance.confirmed_btc,
            unconfirmed_btc=balance.unconfirmed_btc,
            usd_value=usd_value,
            rate_btc_usd=rate,
            rate_updated_at=updated_at,
            rate_is_cached=is_cached,
        )

    async def _fetch_btc_usd_rate(self) -> tuple[float, Optional[datetime], bool]:
        """回傳 (rate, updated_at, is_cached)。

        成功：更新快取，is_cached=False。
        失敗有快取：回傳快取值，is_cached=True。
        失敗無快取：回傳 0.0，is_cached=True。
        """
        client = self._http_client
        owns = False
        if client is None:
            client = httpx.AsyncClient(timeout=10.0)
            owns = True
        try:
            resp = await client.get(self._rate_url)
            resp.raise_for_status()
            data = resp.json()
            rate = float(data["bitcoin"]["usd"])
            self._cached_rate = rate
            self._cached_rate_at = datetime.now(timezone.utc)
            return rate, self._cached_rate_at, False
        except Exception:  # noqa: BLE001 - API 失敗使用快取
            if self._cached_rate is not None:
                return self._cached_rate, self._cached_rate_at, True
            return 0.0, None, True
        finally:
            if owns:
                await client.aclose()

    # ----- 查詢與統計 ----------------------------------------------------- #
    async def query_transactions(
        self, filters: LedgerFilter
    ) -> list[TransactionRecord]:
        return await self.ledger.query(filters)

    async def get_cumulative_stats(self) -> CumulativeStats:
        records = await self.ledger.get_all()
        return compute_cumulative_stats(records)

    async def generate_monthly_report(
        self, year: int, month: Optional[int] = None
    ) -> list[MonthlyReport]:
        records = await self.ledger.get_all()
        return compute_monthly_reports(records, year, month)


# --------------------------------------------------------------------------- #
# 純函式（供 property test 直接驗證）
# --------------------------------------------------------------------------- #
def compute_usd_value(confirmed_btc: float, rate_btc_usd: float) -> float:
    """USD 估值 = confirmed_btc * rate_btc_usd。"""
    return confirmed_btc * rate_btc_usd


def compute_cumulative_stats(records: list[TransactionRecord]) -> CumulativeStats:
    """計算累計統計。"""
    total_btc = sum(r.amount_btc for r in records)
    count = len(records)
    average = total_btc / count if count > 0 else 0.0
    breakdown: dict[str, float] = {}
    for r in records:
        key = r.platform if r.platform else "unknown"
        breakdown[key] = breakdown.get(key, 0.0) + r.amount_btc
    return CumulativeStats(
        total_btc=total_btc,
        transaction_count=count,
        average_btc=average,
        platform_breakdown=breakdown,
    )


def compute_monthly_reports(
    records: list[TransactionRecord],
    year: int,
    month: Optional[int] = None,
) -> list[MonthlyReport]:
    """按月彙總並計算月對月成長率。

    以 (year, month) 分組後依時間排序，growth_rate = (當月 - 上月) / 上月，
    首月（無上月資料）growth_rate 為 None。
    若指定 month，僅回傳該月報表（成長率仍以其前一個有資料月份計算）。
    """
    # 分組：(year, month) -> [total_btc, count]
    groups: dict[tuple[int, int], list[float]] = {}
    for r in records:
        key = (r.confirmed_at.year, r.confirmed_at.month)
        if key not in groups:
            groups[key] = [0.0, 0]
        groups[key][0] += r.amount_btc
        groups[key][1] += 1

    sorted_keys = sorted(groups.keys())
    reports: list[MonthlyReport] = []
    prev_total: Optional[float] = None
    for key in sorted_keys:
        y, m = key
        total, count = groups[key]
        if prev_total is None:
            growth = None
        elif prev_total == 0:
            growth = None  # 除零保護
        else:
            growth = (total - prev_total) / prev_total
        reports.append(
            MonthlyReport(
                year=y, month=m, transaction_count=count,
                total_btc=total, growth_rate=growth,
            )
        )
        prev_total = total

    if month is not None:
        reports = [r for r in reports if r.year == year and r.month == month]
    else:
        reports = [r for r in reports if r.year == year]
    return reports
