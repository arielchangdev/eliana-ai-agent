"""FastAPI Router：人格 / 演化 / 社群端點。

以 create_router(components) 工廠回傳 APIRouter，可掛載於 eliana-core-infra
的 FastAPI app（prefix `/personality`）。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .exceptions import RateLimitExceededError, ValidationError, VersionNotFoundError
from .models import (
    CommunityContext,
    DraftPost,
    PersonalityProfile,
)


@dataclass
class PersonalityComponents:
    """人格模組各元件的容器。"""

    engine: Any = None
    analyzer: Any = None
    evolution: Any = None
    community: Any = None


# --------------------------------------------------------------------------- #
# 請求模型
# --------------------------------------------------------------------------- #
class ExportRequest(BaseModel):
    dest: str
    fmt: str = "json"


class ImportRequest(BaseModel):
    src: str


class AcceptRequest(BaseModel):
    suggestion_ids: list[str]


class RejectRequest(BaseModel):
    parameter_path: str
    direction: str


class RollbackRequest(BaseModel):
    version_id: str


class ComposeRequest(BaseModel):
    platform: str
    topic: str = ""
    prompt_hint: str = ""
    kind: str = "post"  # post | reply


class PublishRequest(BaseModel):
    platform: str
    content: str
    interaction_type: str = "post"


def create_router(components: PersonalityComponents) -> APIRouter:
    router = APIRouter(prefix="/personality", tags=["personality"])

    # ----- 8.1 人格管理 ---------------------------------------------- #
    @router.post("/profile")
    async def set_profile(profile: PersonalityProfile):
        if components.engine is None:
            raise HTTPException(status_code=503, detail="Engine 未初始化")
        result = await components.engine.validate_profile(profile)
        if not result.valid:
            raise HTTPException(status_code=422, detail={"errors": result.errors})
        components.engine.set_active_profile(profile)
        await components.engine.save_profile()
        await components.engine.snapshot_version(source="manual", summary="手動更新人格")
        return {
            "profile": profile.model_dump(mode="json"),
            "warnings": result.warnings,
        }

    @router.get("/profile")
    async def get_profile():
        if components.engine is None:
            raise HTTPException(status_code=503, detail="Engine 未初始化")
        try:
            profile = components.engine.get_active_profile()
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        return profile.model_dump(mode="json")

    @router.post("/export")
    async def export_profile(req: ExportRequest):
        if components.engine is None:
            raise HTTPException(status_code=503, detail="Engine 未初始化")
        path = await components.engine.export_profile(req.dest, req.fmt)
        return {"exported_to": str(path)}

    @router.post("/import")
    async def import_profile(req: ImportRequest):
        if components.engine is None:
            raise HTTPException(status_code=503, detail="Engine 未初始化")
        try:
            profile = await components.engine.import_profile(req.src)
        except ValidationError as e:
            raise HTTPException(status_code=422, detail={"errors": e.errors})
        components.engine.set_active_profile(profile)
        await components.engine.save_profile()
        return profile.model_dump(mode="json")

    # ----- 8.2 演化管理 ---------------------------------------------- #
    @router.get("/evolution/pending")
    async def get_pending():
        if components.evolution is None:
            raise HTTPException(status_code=503, detail="Evolution 未初始化")
        logs = await components.evolution.db.get_evolution_logs(status="pending")
        return {"pending": logs}

    @router.post("/evolution/accept")
    async def accept_evolution(req: AcceptRequest):
        if components.evolution is None:
            raise HTTPException(status_code=503, detail="Evolution 未初始化")
        profile = await components.evolution.accept_pending(req.suggestion_ids)
        return profile.model_dump(mode="json")

    @router.post("/evolution/reject")
    async def reject_evolution(req: RejectRequest):
        if components.evolution is None:
            raise HTTPException(status_code=503, detail="Evolution 未初始化")
        try:
            await components.evolution.reject_direction(
                req.parameter_path, req.direction
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        return {"rejected": True, "parameter_path": req.parameter_path,
                "direction": req.direction}

    @router.get("/evolution/history")
    async def evolution_history(limit: int = 100):
        if components.evolution is None:
            raise HTTPException(status_code=503, detail="Evolution 未初始化")
        history = await components.evolution.get_version_history(limit=limit)
        return {"versions": history}

    @router.post("/evolution/rollback")
    async def rollback(req: RollbackRequest):
        if components.evolution is None:
            raise HTTPException(status_code=503, detail="Evolution 未初始化")
        try:
            profile = await components.evolution.rollback_to_version(req.version_id)
        except VersionNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e))
        return profile.model_dump(mode="json")

    @router.get("/evolution/timeline")
    async def evolution_timeline():
        if components.evolution is None:
            raise HTTPException(status_code=503, detail="Evolution 未初始化")
        timeline = await components.evolution.get_evolution_timeline()
        return {"timeline": timeline}

    # ----- 8.3 社群互動 ---------------------------------------------- #
    @router.post("/community/compose")
    async def compose(req: ComposeRequest):
        if components.community is None:
            raise HTTPException(status_code=503, detail="Community 未初始化")
        ctx = CommunityContext(
            platform=req.platform, topic=req.topic, prompt_hint=req.prompt_hint
        )
        if req.kind == "reply":
            draft = await components.community.compose_reply(ctx)
        else:
            draft = await components.community.compose_post(ctx)
        return draft.model_dump(mode="json")

    @router.post("/community/publish")
    async def publish(req: PublishRequest):
        if components.community is None:
            raise HTTPException(status_code=503, detail="Community 未初始化")
        draft = DraftPost(
            platform=req.platform, content=req.content,
            interaction_type=req.interaction_type,
        )
        try:
            result = await components.community.publish(draft)
        except RateLimitExceededError as e:
            raise HTTPException(status_code=429, detail=str(e))
        if not result.success:
            # 授權被拒 → 403
            raise HTTPException(status_code=403, detail=result.reason)
        return result.model_dump(mode="json")

    @router.get("/community/stats")
    async def community_stats(platform: str):
        if components.community is None:
            raise HTTPException(status_code=503, detail="Community 未初始化")
        count = await components.community.get_daily_count(platform)
        return {"platform": platform, "daily_count": count,
                "remaining": max(0, 5 - count)}

    return router
