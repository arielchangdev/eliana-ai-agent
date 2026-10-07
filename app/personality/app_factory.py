"""元件組裝與依賴注入。

build_components() 組裝四大元件；create_app() 建立可獨立運行的 FastAPI app。
整合至 eliana-core-infra 時可改為在其 app 上 include_router(create_router(...))。
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI

from .analyzer import ConversationAnalyzer
from .community import CommunityAgent
from .db import EvolutionDB
from .engine import PersonalityEngine
from .evolution import EvolutionManager
from .interfaces import (
    AuthorizationGateClient,
    LearningEngineClient,
    OllamaClient,
)
from .models import EvolutionSuggestion, PersonalityProfile, ToneStyle
from .router import PersonalityComponents, create_router

logger = logging.getLogger(__name__)


async def build_components(
    profile_dir: str | Path,
    llm_client: OllamaClient,
    auth_gate: AuthorizationGateClient,
    db_path: str = "data/personality.db",
    learning_engine: Optional[LearningEngineClient] = None,
    http_client=None,
    default_profile: Optional[PersonalityProfile] = None,
) -> tuple[PersonalityComponents, EvolutionDB]:
    """組裝並初始化四大元件的依賴圖。"""
    db = EvolutionDB(db_path)
    await db.init_schema()

    engine = PersonalityEngine(profile_dir, db)
    # 嘗試載入既有 profile，否則使用預設
    try:
        await engine.load_profile()
    except (FileNotFoundError, OSError):
        profile = default_profile or PersonalityProfile(
            tone_styles=[ToneStyle.TECHNICAL, ToneStyle.FRIENDLY]
        )
        engine.set_active_profile(profile)
        await engine.save_profile()
        await engine.snapshot_version(source="manual", summary="初始人格")

    analyzer = ConversationAnalyzer(llm_client, learning_engine)
    evolution = EvolutionManager(db, engine)
    community = CommunityAgent(llm_client, auth_gate, engine, db, http_client)

    components = PersonalityComponents(
        engine=engine, analyzer=analyzer,
        evolution=evolution, community=community,
    )
    return components, db


async def handle_conversation_end(
    components: PersonalityComponents,
    conversation: list[dict],
    conversation_id: Optional[str] = None,
) -> None:
    """對話結束事件處理器：Analyzer → EvolutionManager → Engine 完整流程。

    分析對話 → 提取建議 → 套用（受閾值/冷卻管控）→ 遞減冷卻計數。
    """
    analysis = await components.analyzer.analyze_conversation(
        conversation, conversation_id
    )
    if analysis is None:
        # 分析失敗（逾時/解析錯）→ 跳過本次，不影響人格
        return
    profile = components.engine.get_active_profile()
    suggestion: EvolutionSuggestion = await components.analyzer.extract_suggestions(
        analysis, profile
    )
    await components.evolution.apply_suggestions([suggestion])
    await components.evolution.decrement_cooldowns()


def create_app(components: PersonalityComponents, db: EvolutionDB) -> FastAPI:
    """建立獨立 FastAPI app，掛載人格 router。"""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.personality_components = components
        logger.info("人格模組已就緒")
        yield
        await db.close()
        logger.info("人格模組已關閉")

    app = FastAPI(
        title="Eliana Personality",
        description="Eliana 人格模組 REST API",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(create_router(components))
    return app
