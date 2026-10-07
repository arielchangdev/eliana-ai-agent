"""安全論壇 RSS 訂閱來源爬取器（feedparser）。"""
from __future__ import annotations

from ...models import CrawlSource, RawContent, SourceType
from ...processor.parsers.html_parser import parse_html


class RssFeedCrawler:
    def __init__(self, source: CrawlSource):
        self.source = source

    async def fetch(self, client) -> list[RawContent]:
        resp = await client.get(self.source.url)
        resp.raise_for_status()
        return parse_rss(resp.text, self.source.url)


def parse_rss(feed_text: str, source_url: str) -> list[RawContent]:
    """以 feedparser 解析 RSS/Atom，回傳 RawContent 列表。"""
    try:
        import feedparser
    except ImportError as exc:  # pragma: no cover - 環境相依
        raise RuntimeError("RSS 解析需要 feedparser 套件") from exc

    parsed = feedparser.parse(feed_text)
    results: list[RawContent] = []
    for entry in parsed.entries:
        title = getattr(entry, "title", "")
        summary = getattr(entry, "summary", "") or getattr(entry, "description", "")
        link = getattr(entry, "link", source_url)
        # summary 可能含 HTML
        clean_summary = parse_html(summary) if summary else ""
        text = f"{title}\n{clean_summary}".strip()
        if title or clean_summary:
            results.append(
                RawContent(
                    source_type=SourceType.RSS,
                    source_url=link,
                    text=text,
                    title=title,
                )
            )
    return results
