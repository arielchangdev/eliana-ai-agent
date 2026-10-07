"""來源爬取器共用介面。"""
from __future__ import annotations

from typing import Protocol

from ...models import CrawlSource, RawContent


class SourceCrawler(Protocol):
    """統一來源爬取介面。"""

    source: CrawlSource

    async def fetch(self, client) -> list[RawContent]:
        """使用注入的 http client 爬取，回傳原始內容列表。"""
        ...
