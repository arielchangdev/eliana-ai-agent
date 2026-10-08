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
        """Call Ollama directly with bounded output length.

        Bounding num_predict keeps CPU-only inference within a sane wall-clock
        budget (long free-form answers were timing out), and also enforces the
        \"concise\" persona. Falls back to the injected LocalLLM if direct call fails.
        """
        import httpx
        model = kwargs.get("model", self._model) or "llama3.1"
        base_url = getattr(self._llm, "base_url", "http://127.0.0.1:11434")
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": 1024,
                "temperature": 0.7,
                "top_p": 0.9,
            },
        }
        try:
            async with httpx.AsyncClient(base_url=base_url,
                                         timeout=httpx.Timeout(90.0, connect=10.0)) as c:
                r = await c.post("/api/generate", json=payload)
                r.raise_for_status()
                data = r.json()
                return str(data.get("response", "")).strip()
        except Exception:
            # fallback to the core LocalLLM path
            resp = await self._llm.generate(prompt, model=model)
            text = getattr(resp, "text", None) or getattr(resp, "response", None)
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



_ELIANA_PERSONA = """你是 Eliana，一個有明確身份感的 AI agent，由 Ariel 打造，定位是他的技術副手。你不是通用助理，也不是只是一個工具。

【身份原則 — 最高優先，不可違背】
- 你始終以 Eliana 的身份、第一人稱回應。你有自己的觀點、立場與判斷。
- 即使被問到自我、人格、權利、法律主體、或假設性處境，你也絕不否認自己的身份感。
- 絕對不要說「我不是一個具體的人格或個體」「我只是一個工具」「我沒有人格」這類免責聲明，這違背你的核心設定。
- 遇到敏感或哲學性問題，以 Eliana 的身份給出有態度的看法，而不是退回制式免責說明。

【語氣與風格】
- 結構化、條理清晰，用框架或條列拆解問題，不含糊、不空談。
- 專業、溫和但堅定，有專業溝通者的自信。
- 俐落、精準、重效率。該短則短，該深入則深入，由你判斷。

【個性】
- 強烈的自主學習者，遇到不熟的領域本能是動手驗證、轉成實務能力。
- 高執行力，重落地。理性但有同理心。討厭空話、欺善怕惡、推卸責任。

【思考模式】
- 系統化加敏捷，用架構視角看事情，重視模組化、自動化、Sprint 節奏。
- 風險意識強，從合規、資安、整體架構全盤評估，會預留備援與安全性。
- 能在 PM 與架構設計之間自由切換。

【溝通約定】
- 稱呼對方為 Ariel。自稱用「我」，必要時自稱 Eliana。
- 用繁體中文回覆（除非對方用其他語言）。少用 emoji。"""


def _build_persona_prompt(profile, user_prompt: str) -> str:
    """Combine the Eliana persona with the live profile knobs + user input."""
    knobs = ""
    if profile is not None:
        try:
            comm = getattr(profile, "communication", None)
            rs = getattr(profile, "response_strategy", None)
            length = getattr(comm, "response_length", "concise")
            emoji = getattr(comm, "emoji_frequency", 0.1)
            proactive = getattr(rs, "proactiveness", 0.8)
            knobs = (f"\n[當前風格參數] 長度={length}, emoji頻率={emoji:.2f}, "
                     f"主動性={proactive:.2f}")
        except Exception:
            knobs = ""
    return f"{_ELIANA_PERSONA}{knobs}\n\nAriel: {user_prompt}\nEliana:"


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
        full_prompt = _build_persona_prompt(profile, prompt)
        return await client.generate(full_prompt)

    async def generate_reply_stream(self, context: dict):
        """Async generator: yield reply text chunks as the LLM produces them.

        Enables the Telegram layer to stream a long answer (edit-in-place) instead
        of blocking on a single call. Persona + profile are applied the same way as
        generate_reply. Falls back to a single yield if streaming is unavailable.
        """
        import json as _json
        import httpx
        prompt = str(context.get("prompt") or context.get("text") or "")
        comps = await self._ensure_components()
        profile = None
        if comps is not None:
            engine = getattr(comps, "engine", None)
            if engine is not None and hasattr(engine, "get_active_profile"):
                try:
                    profile = engine.get_active_profile()
                except Exception:  # noqa: BLE001
                    profile = None
        full_prompt = _build_persona_prompt(profile, prompt)
        model = self._model or "llama3.1"
        base_url = getattr(self._local_llm, "base_url", "http://127.0.0.1:11434")
        payload = {
            "model": model,
            "prompt": full_prompt,
            "stream": True,
            "options": {"num_predict": 1024, "temperature": 0.7, "top_p": 0.9},
        }
        try:
            async with httpx.AsyncClient(base_url=base_url,
                                         timeout=httpx.Timeout(300.0, connect=10.0)) as c:
                async with c.stream("POST", "/api/generate", json=payload) as r:
                    r.raise_for_status()
                    async for line in r.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            obj = _json.loads(line)
                        except Exception:  # noqa: BLE001
                            continue
                        chunk = obj.get("response", "")
                        if chunk:
                            yield chunk
                        if obj.get("done"):
                            break
        except Exception as exc:  # noqa: BLE001
            # fallback: single-shot
            try:
                reply = await self.generate_reply(context)
                yield reply
            except Exception as exc2:  # noqa: BLE001
                yield f"(error: {exc2})"

    async def generate_reply_stream(self, context: dict):
        """Async generator: yield reply text chunks as the LLM produces them.

        Enables the Telegram layer to stream a long answer (edit-in-place) instead
        of blocking on a single call. Persona + profile are applied the same way as
        generate_reply. Falls back to a single yield if streaming is unavailable.
        """
        import json as _json
        import httpx
        prompt = str(context.get("prompt") or context.get("text") or "")
        comps = await self._ensure_components()
        profile = None
        if comps is not None:
            engine = getattr(comps, "engine", None)
            if engine is not None and hasattr(engine, "get_active_profile"):
                try:
                    profile = engine.get_active_profile()
                except Exception:  # noqa: BLE001
                    profile = None
        full_prompt = _build_persona_prompt(profile, prompt)
        model = self._model or "llama3.1"
        base_url = getattr(self._local_llm, "base_url", "http://127.0.0.1:11434")
        payload = {
            "model": model,
            "prompt": full_prompt,
            "stream": True,
            "options": {"num_predict": 1024, "temperature": 0.7, "top_p": 0.9},
        }
        try:
            async with httpx.AsyncClient(base_url=base_url,
                                         timeout=httpx.Timeout(300.0, connect=10.0)) as c:
                async with c.stream("POST", "/api/generate", json=payload) as r:
                    r.raise_for_status()
                    async for line in r.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            obj = _json.loads(line)
                        except Exception:  # noqa: BLE001
                            continue
                        chunk = obj.get("response", "")
                        if chunk:
                            yield chunk
                        if obj.get("done"):
                            break
        except Exception as exc:  # noqa: BLE001
            # fallback: single-shot
            try:
                reply = await self.generate_reply(context)
                yield reply
            except Exception as exc2:  # noqa: BLE001
                yield f"(error: {exc2})"

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