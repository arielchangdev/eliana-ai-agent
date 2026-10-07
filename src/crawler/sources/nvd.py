"""NVD / CVE 來源爬取器。"""
from __future__ import annotations

from ...models import CrawlSource, RawContent, SourceType


class NvdCrawler:
    def __init__(self, source: CrawlSource):
        self.source = source

    async def fetch(self, client) -> list[RawContent]:
        """爬取 NVD CVE API（JSON），解析為 RawContent 列表。"""
        resp = await client.get(self.source.url)
        resp.raise_for_status()
        data = resp.json()
        return _parse_nvd(data, self.source.url)


def _parse_nvd(data: dict, source_url: str) -> list[RawContent]:
    """解析 NVD CVE API 2.0 回應。"""
    results: list[RawContent] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        descriptions = cve.get("descriptions", [])
        text = ""
        for d in descriptions:
            if d.get("lang") == "en":
                text = d.get("value", "")
                break
        if not text and descriptions:
            text = descriptions[0].get("value", "")
        # 附加嚴重度資訊
        metrics = cve.get("metrics", {})
        severity_parts = []
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for m in metrics.get(key, []):
                cvss = m.get("cvssData", {})
                score = cvss.get("baseScore")
                if score is not None:
                    severity_parts.append(f"CVSS {score}")
        severity = f" ({', '.join(severity_parts)})" if severity_parts else ""
        full_text = f"{cve_id}{severity}: {text}".strip()
        if full_text and text:
            results.append(
                RawContent(
                    source_type=SourceType.NVD,
                    source_url=source_url,
                    text=full_text,
                    title=cve_id,
                )
            )
    return results
