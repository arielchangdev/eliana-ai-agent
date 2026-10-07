"""Learning_Reporter：每月學習進度報告產生器。

彙整來源：
- Vector_Store：知識庫成長（新增片段、來源分布、分類分布、總容量）
- Strategy_Optimizer / DB：策略效能趨勢、權重調整歷史
- SQLite crawl_logs：爬取健康（成功/失敗/rate_limited）

輸出 Markdown 至 ``{report_dir}/{year}-{month:02d}.md``。
"""
from __future__ import annotations

import calendar
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..db import SQLiteDB
from ..models import (
    CrawlHealthSummary,
    KnowledgeGrowth,
    ReportResult,
    SourceHealth,
    StrategyPerformance,
    StrategyTrend,
    StrategyAdjustment,
)


def _month_range(year: int, month: int) -> tuple[datetime, datetime]:
    """回傳該月份的起訖時間（UTC，含當月最後一刻）。"""
    start = datetime(year, month, 1, tzinfo=timezone.utc)
    last_day = calendar.monthrange(year, month)[1]
    end = datetime(year, month, last_day, 23, 59, 59, tzinfo=timezone.utc)
    return start, end


class LearningReporter:
    def __init__(
        self,
        vector_store,
        optimizer,
        db: SQLiteDB,
        report_dir: str | Path = "data/reports",
    ):
        self.vector_store = vector_store
        self.optimizer = optimizer
        self.db = db
        self.report_dir = Path(report_dir)

    # ----- 主流程 --------------------------------------------------------- #
    async def generate_monthly_report(self, year: int, month: int) -> ReportResult:
        growth = await self.get_knowledge_growth(year, month)
        performance = await self.get_strategy_performance(year, month)
        health = await self.get_crawl_health(year, month)

        markdown = _render_markdown(year, month, growth, performance, health)

        self.report_dir.mkdir(parents=True, exist_ok=True)
        report_path = self.report_dir / f"{year}-{month:02d}.md"
        report_path.write_text(markdown, encoding="utf-8")

        return ReportResult(
            year=year,
            month=month,
            report_path=str(report_path),
            markdown=markdown,
        )

    # ----- 知識庫成長 ----------------------------------------------------- #
    async def get_knowledge_growth(self, year: int, month: int) -> KnowledgeGrowth:
        """本月新增片段數、來源分布、分類分布、總容量。

        以 crawl_logs 統計本月新增片段數（fragments_created 加總），
        以 vector_store 統計整體分類/來源分布與總容量。
        """
        start, end = _month_range(year, month)
        logs = await self.db.get_crawl_logs(date_from=start, date_to=end)
        # 僅成功的爬取才會實際新增片段
        new_fragments = sum(
            int(lg.get("fragments_created", 0))
            for lg in logs
            if lg.get("status") == "success"
        )

        stats = await self.vector_store.get_stats()
        return KnowledgeGrowth(
            new_fragments=new_fragments,
            source_distribution=dict(stats.source_distribution),
            category_distribution=dict(stats.category_distribution),
            total_capacity=stats.total_fragments,
        )

    # ----- 策略效能 ------------------------------------------------------- #
    async def get_strategy_performance(
        self, year: int, month: int
    ) -> StrategyPerformance:
        start, end = _month_range(year, month)
        trends: list[StrategyTrend] = await self.optimizer.get_trends()

        history = await self.db.get_strategy_history(date_from=start, date_to=end)
        adjustments: list[StrategyAdjustment] = [
            StrategyAdjustment(
                strategy_id=h["strategy_id"],
                previous_weight=h["previous_weight"],
                new_weight=h["new_weight"],
                new_status="",
                reason=h.get("trigger_reason", ""),
                success_rate=h.get("success_rate") or 0.0,
            )
            for h in history
        ]

        strategies = await self.db.get_all_strategies()
        new_strategies = [
            s.name for s in strategies if s.status.value == "active"
        ]
        deprecated = [
            s.name for s in strategies if s.status.value == "deprecated"
        ]

        return StrategyPerformance(
            trends=trends,
            weight_adjustments=adjustments,
            new_strategies=new_strategies,
            deprecated_strategies=deprecated,
        )

    # ----- 爬取健康 ------------------------------------------------------- #
    async def get_crawl_health(self, year: int, month: int) -> CrawlHealthSummary:
        start, end = _month_range(year, month)
        logs = await self.db.get_crawl_logs(date_from=start, date_to=end)

        per_source: dict[str, SourceHealth] = {}
        total_success = 0
        total_failed = 0
        total_rate_limited = 0

        for lg in logs:
            st_value = lg["source_type"]
            health = per_source.get(st_value)
            if health is None:
                health = SourceHealth(
                    source_type=st_value,
                    source_url=lg.get("source_url", ""),
                    success_count=0,
                    failure_count=0,
                    rate_limited_count=0,
                )
                per_source[st_value] = health
            status = lg["status"]
            if status == "success":
                health.success_count += 1
                total_success += 1
            elif status == "rate_limited":
                health.rate_limited_count += 1
                total_rate_limited += 1
            else:  # failed / skipped
                health.failure_count += 1
                total_failed += 1

        return CrawlHealthSummary(
            per_source=per_source,
            total_success=total_success,
            total_failed=total_failed,
            total_rate_limited=total_rate_limited,
        )


# --------------------------------------------------------------------------- #
# Markdown 渲染
# --------------------------------------------------------------------------- #
def _render_markdown(
    year: int,
    month: int,
    growth: KnowledgeGrowth,
    performance: StrategyPerformance,
    health: CrawlHealthSummary,
) -> str:
    lines: list[str] = []
    lines.append(f"# Eliana 學習進度報告 — {year} 年 {month:02d} 月")
    lines.append("")
    lines.append(f"產生時間：{datetime.now(timezone.utc).isoformat()}")
    lines.append("")

    # 1. 知識庫成長
    lines.append("## 一、知識庫成長")
    lines.append("")
    lines.append(f"- 本月新增片段數：**{growth.new_fragments}**")
    lines.append(f"- 知識庫總容量：**{growth.total_capacity}** 片段")
    lines.append("")
    lines.append("### 來源分布")
    lines.append("")
    if growth.source_distribution:
        lines.append("| 來源 | 片段數 |")
        lines.append("|------|--------|")
        for src, cnt in sorted(growth.source_distribution.items()):
            lines.append(f"| {src} | {cnt} |")
    else:
        lines.append("（無資料）")
    lines.append("")
    lines.append("### 分類標籤分布")
    lines.append("")
    if growth.category_distribution:
        lines.append("| 分類 | 片段數 |")
        lines.append("|------|--------|")
        for tag, cnt in sorted(growth.category_distribution.items()):
            lines.append(f"| {tag} | {cnt} |")
    else:
        lines.append("（無資料）")
    lines.append("")

    # 2. 策略效能
    lines.append("## 二、策略效能")
    lines.append("")
    lines.append("### 各策略成功率趨勢")
    lines.append("")
    if performance.trends:
        lines.append("| 策略 | 成功率 | 目前權重 | 權重調整次數 |")
        lines.append("|------|--------|----------|--------------|")
        for t in performance.trends:
            lines.append(
                f"| {t.name} | {t.success_rate:.0%} | {t.current_weight:.2f} | {t.weight_changes} |"
            )
    else:
        lines.append("（無策略資料）")
    lines.append("")
    lines.append("### 權重調整歷史")
    lines.append("")
    if performance.weight_adjustments:
        lines.append("| 策略 ID | 調整前 | 調整後 | 觸發原因 |")
        lines.append("|---------|--------|--------|----------|")
        for a in performance.weight_adjustments:
            lines.append(
                f"| {a.strategy_id} | {a.previous_weight:.2f} | {a.new_weight:.2f} | {a.reason} |"
            )
    else:
        lines.append("本月無權重調整。")
    lines.append("")
    lines.append(
        f"- 新增策略：{', '.join(performance.new_strategies) or '無'}"
    )
    lines.append(
        f"- 淘汰策略：{', '.join(performance.deprecated_strategies) or '無'}"
    )
    lines.append("")

    # 3. 爬取健康
    lines.append("## 三、爬取健康狀況")
    lines.append("")
    lines.append(
        f"- 總成功：**{health.total_success}**　"
        f"總失敗：**{health.total_failed}**　"
        f"速率限制觸發：**{health.total_rate_limited}**"
    )
    lines.append("")
    if health.per_source:
        lines.append("| 來源 | 成功 | 失敗 | 速率限制 | 成功率 |")
        lines.append("|------|------|------|----------|--------|")
        for src, h in sorted(health.per_source.items()):
            lines.append(
                f"| {src} | {h.success_count} | {h.failure_count} | "
                f"{h.rate_limited_count} | {h.success_rate:.0%} |"
            )
    else:
        lines.append("（本月無爬取紀錄）")
    lines.append("")

    return "\n".join(lines)
