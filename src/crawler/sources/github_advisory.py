"""GitHub Security Advisories 來源爬取器。"""
from __future__ import annotations

from ...models import CrawlSource, RawContent, SourceType


class GitHubAdvisoryCrawler:
    def __init__(self, source: CrawlSource):
        self.source = source

    async def fetch(self, client) -> list[RawContent]:
        resp = await client.get(self.source.url)
        resp.raise_for_status()
        data = resp.json()
        return _parse_advisories(data, self.source.url)


def _parse_advisories(data, source_url: str) -> list[RawContent]:
    """解析 GitHub Advisories API 回應（JSON 陣列）。"""
    results: list[RawContent] = []
    items = data if isinstance(data, list) else data.get("advisories", [])
    for adv in items:
        ghsa_id = adv.get("ghsa_id") or adv.get("id", "GHSA-UNKNOWN")
        summary = adv.get("summary", "")
        description = adv.get("description", "")
        severity = adv.get("severity", "")
        text = f"{ghsa_id} [{severity}]: {summary}\n{description}".strip()
        if summary or description:
            results.append(
                RawContent(
                    source_type=SourceType.GITHUB_ADVISORY,
                    source_url=adv.get("html_url", source_url),
                    text=text,
                    title=summary or ghsa_id,
                )
            )
    return results
