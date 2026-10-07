"""Knowledge_Crawler：技術社群爬蟲主元件。

協調流程：檢查 robots.txt → 爬取（HTTP 429/逾時觸發指數退避）→
Local_LLM 摘要 → Material_Processor 寫入向量庫 → 記錄爬取事件。
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional

from ..interfaces import Summarizer
from ..models import (
    CrawlResult,
    CrawlSource,
    RawContent,
    SourceHealth,
    SourceMeta,
    SourceType,
)
from .backoff import MaxRetriesExceeded, retry_with_backoff
from .robots_checker import check_robots_txt
from .sources.exploit_db import ExploitDbCrawler
from .sources.github_advisory import GitHubAdvisoryCrawler
from .sources.nvd import NvdCrawler
from .sources.rss_feed import RssFeedCrawler

# 觸發退避重試的 HTTP 狀態碼
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}

_SOURCE_CRAWLERS = {
    SourceType.NVD: NvdCrawler,
    SourceType.GITHUB_ADVISORY: GitHubAdvisoryCrawler,
    SourceType.EXPLOIT_DB: ExploitDbCrawler,
    SourceType.RSS: RssFeedCrawler,
}


def _is_retryable(exc: Exception) -> bool:
    """判斷例外是否應觸發退避重試（429/逾時/連線錯誤）。"""
    import httpx

    if isinstance(exc, httpx.TimeoutException):
        return True
    if isinstance(exc, httpx.ConnectError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in _RETRYABLE_STATUS
    # 一般 RequestError（含 DNS 解析失敗）視為可重試
    if isinstance(exc, httpx.RequestError):
        return True
    return False


class KnowledgeCrawler:
    def __init__(
        self,
        http_client,
        processor,
        db,
        summarizer: Optional[Summarizer] = None,
        sources: Optional[list[CrawlSource]] = None,
        sleep=None,
    ):
        self.http_client = http_client
        self.processor = processor
        self.db = db
        self.summarizer = summarizer
        self.sources = sources or []
        # 注入式 sleep，測試可傳入無等待版本
        self._sleep = sleep

    # ----- 主流程 --------------------------------------------------------- #
    async def start_crawl(
        self, sources: Optional[list[CrawlSource]] = None
    ) -> CrawlResult:
        """啟動完整爬取循環。"""
        targets = sources if sources is not None else self.sources
        attempted = 0
        succeeded = 0
        skipped = 0
        total_fragments = 0
        errors: list[str] = []

        for source in targets:
            attempted += 1
            try:
                fragments = await self._crawl_one(source)
                total_fragments += fragments
                succeeded += 1
            except _SkippedSource as exc:
                skipped += 1
                errors.append(str(exc))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{source.source_type.value} 爬取失敗: {exc}")

        return CrawlResult(
            sources_attempted=attempted,
            sources_succeeded=succeeded,
            sources_skipped=skipped,
            fragments_created=total_fragments,
            errors=errors,
        )

    async def _crawl_one(self, source: CrawlSource) -> int:
        """爬取單一來源，回傳新增片段數。"""
        start = time.monotonic()

        # 1. robots.txt 檢查
        if source.robots_respected:
            allowed = await check_robots_txt(source.url, self.http_client)
            if not allowed:
                await self.db.insert_crawl_log(
                    source_type=source.source_type.value,
                    source_url=source.url,
                    status="skipped",
                    error_message="robots.txt 禁止爬取",
                )
                raise _SkippedSource(f"{source.source_type.value}: robots.txt 禁止")

        # 2. 爬取（含指數退避）
        try:
            raw_contents = await self._fetch_with_retry(source)
        except MaxRetriesExceeded as exc:
            await self.db.insert_crawl_log(
                source_type=source.source_type.value,
                source_url=source.url,
                status="rate_limited",
                error_message=str(exc),
                duration_ms=int((time.monotonic() - start) * 1000),
            )
            raise _SkippedSource(
                f"{source.source_type.value}: 連續失敗已跳過"
            ) from exc

        # 3. 摘要 + 4. 寫入向量庫
        fragments_created = 0
        for raw in raw_contents:
            text = await self._summarize(raw)
            source_meta = SourceMeta(
                source_type=raw.source_type,
                source_url=raw.source_url,
            )
            result = await self.processor.process_text(text, source_meta)
            fragments_created += result.fragments_created

        # 5. 記錄成功事件
        await self.db.insert_crawl_log(
            source_type=source.source_type.value,
            source_url=source.url,
            status="success",
            fragments_created=fragments_created,
            duration_ms=int((time.monotonic() - start) * 1000),
        )
        return fragments_created

    async def _fetch_with_retry(self, source: CrawlSource) -> list[RawContent]:
        crawler_cls = _SOURCE_CRAWLERS.get(source.source_type)
        if crawler_cls is None:
            raise ValueError(f"未知來源類型: {source.source_type}")
        crawler = crawler_cls(source)

        async def _op() -> list[RawContent]:
            return await crawler.fetch(self.http_client)

        kwargs = {}
        if self._sleep is not None:
            kwargs["sleep"] = self._sleep
        return await retry_with_backoff(
            _op, source.retry_config, should_retry=_is_retryable, **kwargs
        )

    async def _summarize(self, raw: RawContent) -> str:
        if self.summarizer is not None:
            try:
                summary = await self.summarizer.summarize(raw.text)
                if summary and summary.strip():
                    return summary
            except Exception:  # noqa: BLE001 - 摘要失敗退回原文
                pass
        return raw.text

    # ----- 健康狀態 ------------------------------------------------------- #
    async def get_health(self) -> dict[str, SourceHealth]:
        """回傳各來源的健康狀態統計。"""
        health: dict[str, SourceHealth] = {}
        for source in self.sources:
            st_value = source.source_type.value
            logs = await self.db.get_crawl_logs(source_type=st_value)
            success = sum(1 for lg in logs if lg["status"] == "success")
            failed = sum(1 for lg in logs if lg["status"] in ("failed", "skipped"))
            rate_limited = sum(1 for lg in logs if lg["status"] == "rate_limited")
            last_crawled = None
            if logs:
                last_crawled = _parse_iso(logs[0].get("created_at"))
            health[st_value] = SourceHealth(
                source_type=st_value,
                source_url=source.url,
                success_count=success,
                failure_count=failed,
                rate_limited_count=rate_limited,
                last_crawled_at=last_crawled,
            )
        return health


class _SkippedSource(Exception):
    """來源被跳過（robots 禁止或連續失敗）。"""


def _parse_iso(value) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    try:
        # SQLite CURRENT_TIMESTAMP 格式 'YYYY-MM-DD HH:MM:SS'
        return datetime.fromisoformat(value.replace(" ", "T")).replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None
