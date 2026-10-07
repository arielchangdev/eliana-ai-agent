"""CommunityAgent：社群互動代理。

- compose_post / compose_reply：依人格用 Local_LLM 生成草稿
- request_authorization：經 Authorization_Gate 取得許可（不可達 → 安全降級為拒絕）
- publish：發送已授權內容，受每日 5 則速率限制
- check_rate_limit：每平台每日上限 5 則
"""
from __future__ import annotations

import logging
from typing import Optional
from uuid import uuid4

from .db import EvolutionDB
from .engine import PersonalityEngine
from .exceptions import RateLimitExceededError
from .interfaces import AuthorizationGateClient, OllamaClient
from .models import AuthResult, CommunityContext, DraftPost, PublishResult

logger = logging.getLogger(__name__)

DAILY_LIMIT = 5


class CommunityAgent:
    def __init__(
        self,
        llm_client: OllamaClient,
        auth_gate: AuthorizationGateClient,
        engine: PersonalityEngine,
        db: EvolutionDB,
        http_client=None,
    ):
        self.llm = llm_client
        self.auth_gate = auth_gate
        self.engine = engine
        self.db = db
        self.http = http_client

    # ----- 內容生成 ------------------------------------------------------- #
    async def compose_post(self, context: CommunityContext) -> DraftPost:
        """依人格生成貼文草稿。"""
        prompt = self._build_prompt(context, kind="post")
        content = await self.llm.generate(prompt)
        return DraftPost(
            platform=context.platform, content=content, interaction_type="post"
        )

    async def compose_reply(self, context: CommunityContext) -> DraftPost:
        """依人格生成回覆草稿。"""
        prompt = self._build_prompt(context, kind="reply")
        content = await self.llm.generate(prompt)
        return DraftPost(
            platform=context.platform, content=content, interaction_type="reply"
        )

    def _build_prompt(self, context: CommunityContext, kind: str) -> str:
        profile = self.engine.get_active_profile()
        tones = ", ".join(t.value for t in profile.tone_styles)
        return (
            f"以下列人格生成一則{kind}：\n"
            f"語氣風格：{tones}\n"
            f"表情符號頻率：{profile.communication.emoji_frequency}\n"
            f"平台：{context.platform}\n主題：{context.topic}\n"
            f"提示：{context.prompt_hint}"
        )

    # ----- 授權流程 ------------------------------------------------------- #
    async def request_authorization(self, draft: DraftPost) -> AuthResult:
        """經 Authorization_Gate 請求許可。不可達 → 安全降級為拒絕。"""
        description = (
            f"發送{draft.interaction_type}至 {draft.platform}: "
            f"{draft.content[:80]}"
        )
        try:
            resp = await self.auth_gate.request(description, risk_level="low")
        except Exception:  # noqa: BLE001 - 不可達視為拒絕（安全降級）
            logger.warning("Authorization_Gate 不可達，安全降級為拒絕")
            return AuthResult(authorized=False, reason="gate_unavailable")
        return AuthResult(
            authorized=bool(resp.get("authorized", False)),
            reason=str(resp.get("reason", "")),
        )

    # ----- 發送與速率限制 ------------------------------------------------- #
    async def check_rate_limit(self, platform: str) -> bool:
        """每平台每日上限 DAILY_LIMIT 則；未達上限回傳 True。"""
        count = await self.db.get_daily_interaction_count(platform)
        return count < DAILY_LIMIT

    async def get_daily_count(self, platform: str) -> int:
        return await self.db.get_daily_interaction_count(platform)

    async def publish(self, draft: DraftPost) -> PublishResult:
        """發送流程：速率檢查 → 授權 → 發送。

        - 超出速率 → RateLimitExceededError
        - 授權拒絕/不可達 → 記錄拒絕原因，回傳 success=False
        - 授權通過 → 發送並記錄互動
        """
        # 1. 速率限制
        if not await self.check_rate_limit(draft.platform):
            count = await self.get_daily_count(draft.platform)
            raise RateLimitExceededError(draft.platform, count)

        # 2. 授權
        auth = await self.request_authorization(draft)
        if not auth.authorized:
            # 記錄拒絕
            await self.db.insert_interaction(
                interaction_id=str(uuid4()),
                platform=draft.platform,
                interaction_type=draft.interaction_type,
                content_preview=draft.content[:120],
                rejected_reason=auth.reason or "rejected",
            )
            return PublishResult(success=False, reason=auth.reason or "rejected")

        # 3. 發送（真實整合時透過 http 發送至平台 API）
        interaction_id = str(uuid4())
        published_at = _utcnow_iso()
        if self.http is not None:
            try:
                await self._send_to_platform(draft)
            except Exception as exc:  # noqa: BLE001
                await self.db.insert_interaction(
                    interaction_id=interaction_id,
                    platform=draft.platform,
                    interaction_type=draft.interaction_type,
                    content_preview=draft.content[:120],
                    rejected_reason=f"send_failed: {exc}",
                )
                return PublishResult(success=False, reason=f"send_failed: {exc}")

        await self.db.insert_interaction(
            interaction_id=interaction_id,
            platform=draft.platform,
            interaction_type=draft.interaction_type,
            content_preview=draft.content[:120],
            authorized_by="authorization_gate",
            published_at=published_at,
        )
        return PublishResult(success=True, interaction_id=interaction_id)

    async def _send_to_platform(self, draft: DraftPost) -> None:
        """透過 http client 發送至平台 API（整合階段接真實端點）。"""
        # 佔位：真實整合時實作平台特定發送邏輯
        return None


def _utcnow_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
