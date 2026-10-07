"""Personality subsystem adapter (support-type subsystem, peer to LearningAdapter).

Personality is NOT a bug-bounty pipeline stage. Like the learning engine, it is a
support-type subsystem: it influences how the agent talks and how its persona evolves.
This adapter implements PersonalityPort and wires the personality engine onto the
local LLM (Ollama) that core-infra already provides.

Design mirrors LearningAdapter: lazy initialization, graceful degradation, and a
narrow Port surface. No personality-module internals are modified.
"""
from __future__ import annotations

import asyncio
from typing import Any, Optional

import structlog

from .subsystems import SubsystemNotWired

logger = structlog.get_logger(__name__)


class _LocalLLMOllamaClient:
    """Adapt core-infra LocalLLM (returns LLMResponse) to personality's
    OllamaClient Protocol (async generate(prompt, **kwargs) -> str)."""

    def __init__(self, local_llm: Any, model: Optional[str] = None) -> None:
        self._llm = local_llm
        self._model = model

    async def generate(self, prompt: str, **kwargs: Any) -> str:
        model = kwargs.get("model", self._model)
        resp = await self._llm.generate(prompt, model=model)
        # LLMResponse -> str (be liberal about the field name)
        text = getattr(resp, "text", None)
        if text is None:
            text = getattr(resp, "response", None)
        return str(text if text is not None else resp)


class _DefaultDenyAuthGate:
    """Safe default AuthorizationGateClient: deny unless a real gate is wired.

    Community publishing requires authorization; until the bounty Authorization_Gate
    is bridged in, personality may still run (compose drafts) but publishing is denied.
    """

    async def request(self, description: str, risk_level: str = "low") -> dict:
        logger.info("personality_auth_default_deny", description=description,
                    risk_level=risk_level)
        return {"authorized": False, "reason": "no authorization gate wired (default deny)"}


class PersonalityAdapter:
    """Implements subsystems.PersonalityPort.

    Lazily builds the personality components (engine/analyzer/evolution/community)
    on first use, wiring them onto the provided local LLM. Mirrors LearningAdapter's
    graceful-degradation contract: if components cannot be built, methods degrade.
    """

    def __init__(
        self,
        *,
        local_llm: Any | None = None,
        profile_dir: str = "data/personality_profiles",
        db_path: str = "data/personality.db",
        model: Optional[str] = None,
        auth_gate: Any | None = None,
    ) -> None:
        self._local_llm = local_llm
        self._profile_dir = profile_dir
        self._db_path = db_path
        self._model = model
        self._auth_gate = auth_gate or _DefaultDenyAuthGate()
        self._components = None
        self._db = None
        self._init_lock: Optional[asyncio.Lock] = None

    async def _ensure_components(self):
        if self._components is not None:
            return self._components
        if self._local_llm is None:
            return None
        if self._init_lock is None:
            self._init_lock = asyncio.Lock()
        async with self._init_lock:
            if self._components is None:
                try:
                    from app.personality.app_factory import build_components
                    llm_client = _LocalLLMOllamaClient(self._local_llm, self._model)
                    components, db = await build_components(
                        profile_dir=self._profile_dir,
                        llm_client=llm_client,
                        auth_gate=self._auth_gate,
                        db_path=self._db_path,
                    )
                    self._components = components
                    self._db = db
                    logger.info("personality_components_initialized",
                                profile_dir=self._profile_dir, db_path=self._db_path)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("personality_init_failed", error=str(exc))
                    return None
        return self._components

    # ----- PersonalityPort surface ----- #
    async def generate_reply(self, context: dict) -> str:
        """Produce a reply using the active persona + local LLM.

        context: {"prompt": str} or {"text": str}. Returns a persona-flavored string.
        Degrades to a plain LLM call if persona composition is unavailable.
        """
        prompt = str(context.get("prompt") or context.get("text") or "")
        comps = await self._ensure_components()
        if comps is None:
            # degrade: direct LLM if available, else signal not wired
            if self._local_llm is not None:
                client = _LocalLLMOllamaClient(self._local_llm, self._model)
                return await client.generate(prompt)
            raise SubsystemNotWired("personality not wired and no local LLM")
        # Compose through the community/engine path when available; fall back to LLM.
        engine = getattr(comps, "engine", None)
        profile = None
        if engine is not None and hasattr(engine, "get_active_profile"):
            try:
                profile = engine.get_active_profile()
            except Exception:  # noqa: BLE001
                profile = None
        client = _LocalLLMOllamaClient(self._local_llm, self._model)
        if profile is not None:
            tone = getattr(profile, "tone_styles", None)
            persona_hint = f"[persona tone: {tone}]\n" if tone else ""
            return await client.generate(persona_hint + prompt)
        return await client.generate(prompt)

    async def observe_conversation(self, conversation: dict) -> None:
        """Feed a finished conversation to the evolution path (if wired).

        Non-fatal: logs and returns on any failure, mirroring learning feedback.
        """
        comps = await self._ensure_components()
        if comps is None:
            logger.debug("personality_not_wired_skip_observe")
            return
        analyzer = getattr(comps, "analyzer", None)
        if analyzer is None or not hasattr(analyzer, "analyze_conversation"):
            logger.debug("personality_analyzer_unavailable")
            return
        try:
            await analyzer.analyze_conversation(conversation)
        except Exception as exc:  # noqa: BLE001
            logger.warning("personality_observe_failed", error=str(exc))

    async def health(self) -> dict:
        """Lightweight health: report whether components are initialized."""
        wired = self._components is not None
        return {"subsystem": "personality", "wired": wired,
                "llm": self._local_llm is not None}