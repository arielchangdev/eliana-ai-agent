"""FastAPI 端點整合。

提供 ``create_router(components)`` 工廠，回傳可掛載於 eliana-core-infra
FastAPI app 的 APIRouter。所有 learning-engine 相關端點集中於此。

同時提供 ``register_schedules(scheduler, ...)`` 向 Task_Scheduler 註冊
週期性任務（每日爬取、每週向量庫優化、每月報告）。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

from .models import (
    CategoryTag,
    SearchFilters,
    SourceMeta,
    SourceType,
    TaskResult,
    UploadMeta,
)


@dataclass
class LearningComponents:
    """learning-engine 各元件的容器。"""

    crawler: Any = None
    processor: Any = None
    vector_store: Any = None
    optimizer: Any = None
    reporter: Any = None


# --------------------------------------------------------------------------- #
# 請求 / 回應 模型
# --------------------------------------------------------------------------- #
class SearchRequest(BaseModel):
    query: str
    top_k: int = 10
    category_tags: Optional[list[str]] = None
    source_types: Optional[list[str]] = None
    date_from: Optional[str] = None
    date_to: Optional[str] = None


class TaskResultRequest(BaseModel):
    task_id: str
    strategy_id: str
    target_type: str
    outcome: str  # success | failure | rejected
    details: Optional[str] = None


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _to_search_filters(req: SearchRequest) -> Optional[SearchFilters]:
    tags = None
    if req.category_tags:
        tags = []
        for t in req.category_tags:
            try:
                tags.append(CategoryTag(t))
            except ValueError:
                raise HTTPException(status_code=400, detail=f"未知分類標籤: {t}")
    sources = None
    if req.source_types:
        sources = []
        for s in req.source_types:
            try:
                sources.append(SourceType(s))
            except ValueError:
                raise HTTPException(status_code=400, detail=f"未知來源類型: {s}")
    if not any([tags, sources, req.date_from, req.date_to]):
        return None
    return SearchFilters(
        category_tags=tags,
        source_types=sources,
        date_from=_parse_iso(req.date_from),
        date_to=_parse_iso(req.date_to),
    )


# --------------------------------------------------------------------------- #
# Router 工廠
# --------------------------------------------------------------------------- #
def create_router(components: LearningComponents) -> APIRouter:
    router = APIRouter(prefix="/api/learning", tags=["learning"])

    # ----- 11.1 爬取與教材處理 --------------------------------------- #
    @router.post("/crawl/start")
    async def start_crawl():
        if components.crawler is None:
            raise HTTPException(status_code=503, detail="Crawler 未初始化")
        result = await components.crawler.start_crawl()
        return {
            "sources_attempted": result.sources_attempted,
            "sources_succeeded": result.sources_succeeded,
            "sources_skipped": result.sources_skipped,
            "fragments_created": result.fragments_created,
            "errors": result.errors,
        }

    @router.get("/crawl/health")
    async def crawl_health():
        if components.crawler is None:
            raise HTTPException(status_code=503, detail="Crawler 未初始化")
        health = await components.crawler.get_health()
        return {
            src: {
                "source_type": h.source_type,
                "success_count": h.success_count,
                "failure_count": h.failure_count,
                "rate_limited_count": h.rate_limited_count,
                "success_rate": h.success_rate,
                "last_crawled_at": h.last_crawled_at.isoformat()
                if h.last_crawled_at
                else None,
            }
            for src, h in health.items()
        }

    @router.post("/material/upload")
    async def upload_material(file: UploadFile = File(...)):
        if components.processor is None:
            raise HTTPException(status_code=503, detail="Processor 未初始化")
        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="檔案內容為空")
        # 以純文字入口處理（若為文字類型），否則需落地為檔案
        import tempfile
        import os

        suffix = os.path.splitext(file.filename or "")[1]
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=suffix
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            result = await components.processor.process_file(
                tmp_path, UploadMeta(filename=file.filename or "upload")
            )
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return {
            "fragments_created": result.fragments_created,
            "total_tokens": result.total_tokens,
            "category_distribution": result.category_distribution,
            "errors": result.errors,
        }

    # ----- 11.2 向量庫與策略 ----------------------------------------- #
    @router.post("/search")
    async def search(req: SearchRequest):
        if components.vector_store is None:
            raise HTTPException(status_code=503, detail="VectorStore 未初始化")
        filters = _to_search_filters(req)
        results = await components.vector_store.search(
            req.query, top_k=req.top_k, filters=filters
        )
        return {
            "results": [
                {
                    "id": r.fragment.id,
                    "text": r.fragment.text,
                    "source_type": r.fragment.source_type.value,
                    "source_url": r.fragment.source_url,
                    "category_tags": [t.value for t in r.fragment.category_tags],
                    "score": r.score,
                }
                for r in results
            ]
        }

    @router.get("/store/stats")
    async def store_stats():
        if components.vector_store is None:
            raise HTTPException(status_code=503, detail="VectorStore 未初始化")
        stats = await components.vector_store.get_stats()
        return {
            "total_fragments": stats.total_fragments,
            "category_distribution": stats.category_distribution,
            "source_distribution": stats.source_distribution,
        }

    @router.post("/strategy/result")
    async def strategy_result(req: TaskResultRequest):
        if components.optimizer is None:
            raise HTTPException(status_code=503, detail="Optimizer 未初始化")
        if req.outcome not in ("success", "failure", "rejected"):
            raise HTTPException(status_code=400, detail="outcome 值無效")
        await components.optimizer.record_result(
            TaskResult(
                task_id=req.task_id,
                strategy_id=req.strategy_id,
                target_type=req.target_type,
                outcome=req.outcome,
                details=req.details,
            )
        )
        adjustments = await components.optimizer.evaluate_strategies()
        alert = await components.optimizer.check_alert_condition()
        return {
            "recorded": True,
            "adjustments": [
                {
                    "strategy_id": a.strategy_id,
                    "previous_weight": a.previous_weight,
                    "new_weight": a.new_weight,
                    "new_status": a.new_status,
                    "reason": a.reason,
                }
                for a in adjustments
            ],
            "global_alert": alert,
        }

    @router.get("/strategy/trends")
    async def strategy_trends(months: int = 1):
        if components.optimizer is None:
            raise HTTPException(status_code=503, detail="Optimizer 未初始化")
        trends = await components.optimizer.get_trends(months=months)
        return {
            "trends": [
                {
                    "strategy_id": t.strategy_id,
                    "name": t.name,
                    "success_rate": t.success_rate,
                    "current_weight": t.current_weight,
                    "weight_changes": t.weight_changes,
                }
                for t in trends
            ]
        }

    # ----- 11.3 報告 ------------------------------------------------- #
    @router.get("/reports/{year}/{month}")
    async def get_report(year: int, month: int):
        if components.reporter is None:
            raise HTTPException(status_code=503, detail="Reporter 未初始化")
        if not (1 <= month <= 12):
            raise HTTPException(status_code=400, detail="月份需介於 1-12")
        result = await components.reporter.generate_monthly_report(year, month)
        return {
            "year": result.year,
            "month": result.month,
            "report_path": result.report_path,
            "markdown": result.markdown,
        }

    return router


# --------------------------------------------------------------------------- #
# 排程註冊（Task 11.3）
# --------------------------------------------------------------------------- #
def register_schedules(
    scheduler: Any,
    components: LearningComponents,
    daily_crawl_cron: str = "0 2 * * *",
    vector_optimize_cron: str = "0 5 * * 0",
    monthly_report_cron: str = "0 0 1 * *",
) -> None:
    """向 Task_Scheduler 註冊週期性任務。

    scheduler 需提供 ``add_job(func, cron, name)`` 或相容介面。
    此函式僅負責註冊，實際排程執行由 core-infra 的 Task_Scheduler 負責。
    """

    async def _daily_crawl():
        if components.crawler is not None:
            await components.crawler.start_crawl()

    async def _weekly_optimize():
        if components.vector_store is not None:
            await components.vector_store.archive_stale(days=180)

    async def _monthly_report():
        if components.reporter is not None:
            now = datetime.now(timezone.utc)
            await components.reporter.generate_monthly_report(now.year, now.month)

    scheduler.add_job(_daily_crawl, daily_crawl_cron, name="learning_daily_crawl")
    scheduler.add_job(
        _weekly_optimize, vector_optimize_cron, name="learning_vector_optimize"
    )
    scheduler.add_job(
        _monthly_report, monthly_report_cron, name="learning_monthly_report"
    )
