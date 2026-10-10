"""Personality subsystem adapter (support-type subsystem, peer to LearningAdapter).

Wires the personality engine onto a pluggable LLM backend:
- local  -> Ollama (on-box, autonomous, slower on CPU)
- gemini -> Google Gemini API (fast, strong persona; needs API key)

Backend chosen via env ELIANA_LLM_BACKEND (default: local). Secrets come from env.
No personality-module internals are modified.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any, Optional

import structlog

from .subsystems import SubsystemNotWired

logger = structlog.get_logger(__name__)


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


def _build_persona_prompt(profile, user_prompt: str, history=None) -> str:
    knobs = ""
    if profile is not None:
        try:
            comm = getattr(profile, "communication", None)
            rs = getattr(profile, "response_strategy", None)
            length = getattr(comm, "response_length", "concise")
            emoji = getattr(comm, "emoji_frequency", 0.1)
            proactive = getattr(rs, "proactiveness", 0.8)
            knobs = f"\n[風格參數] 長度={length}, emoji={emoji:.2f}, 主動性={proactive:.2f}"
        except Exception:
            knobs = ""
    convo = ""
    if history:
        lines = []
        for turn in history:
            u = turn.get("user", "")
            a = turn.get("assistant", "")
            if u:
                lines.append(f"Ariel: {u}")
            if a:
                lines.append(f"Eliana: {a}")
        if lines:
            convo = "\n\n[先前對話，供你保持連貫]\n" + "\n".join(lines)
    return f"{_ELIANA_PERSONA}{knobs}{convo}\n\nAriel: {user_prompt}\nEliana:"


# --------------------------------------------------------------------------- #
# LLM backends (both expose: async generate(prompt)->str, async stream(prompt))
# --------------------------------------------------------------------------- #
class _OllamaBackend:
    def __init__(self, local_llm: Any, model: Optional[str]) -> None:
        self._llm = local_llm
        self._model = model or "llama3.1"
        self._base = getattr(local_llm, "base_url", "http://127.0.0.1:11434")

    async def generate(self, prompt: str) -> str:
        import httpx
        payload = {"model": self._model, "prompt": prompt, "stream": False,
                   "options": {"num_predict": 1024, "temperature": 0.7, "top_p": 0.9}}
        async with httpx.AsyncClient(base_url=self._base,
                                     timeout=httpx.Timeout(120.0, connect=10.0)) as c:
            r = await c.post("/api/generate", json=payload)
            r.raise_for_status()
            return str(r.json().get("response", "")).strip()

    async def stream(self, prompt: str):
        import json as _json
        import httpx
        payload = {"model": self._model, "prompt": prompt, "stream": True,
                   "options": {"num_predict": 1024, "temperature": 0.7, "top_p": 0.9}}
        async with httpx.AsyncClient(base_url=self._base,
                                     timeout=httpx.Timeout(300.0, connect=10.0)) as c:
            async with c.stream("POST", "/api/generate", json=payload) as r:
                r.raise_for_status()
                async for line in r.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        obj = _json.loads(line)
                    except Exception:
                        continue
                    chunk = obj.get("response", "")
                    if chunk:
                        yield chunk
                    if obj.get("done"):
                        break


class _GeminiBackend:
    """Google Gemini backend with 503 retry/backoff (learned from Angelina)."""

    def __init__(self, api_key: str, model: Optional[str]) -> None:
        self._key = api_key
        self._model = model or "gemini-2.5-flash"
        self._base = "https://generativelanguage.googleapis.com/v1beta"

    def _url(self) -> str:
        return f"{self._base}/models/{self._model}:generateContent?key={self._key}"

    async def generate(self, prompt: str) -> str:
        import httpx
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        delays = [0, 2, 4, 8, 12]
        last = None
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as c:
            for d in delays:
                if d:
                    await asyncio.sleep(d)
                try:
                    r = await c.post(self._url(), json=payload)
                    if r.status_code in (503, 429, 500, 502, 504):
                        last = f"HTTP {r.status_code}"
                        continue
                    r.raise_for_status()
                    data = r.json()
                    return data["candidates"][0]["content"]["parts"][0]["text"].strip()
                except Exception as exc:  # noqa: BLE001
                    last = repr(exc)
                    continue
        raise RuntimeError(f"gemini failed after retries: {last}")

    async def classify(self, text: str) -> str:
        """Layer-2 lightweight sensitivity classification. Returns 'SENSITIVE' or 'NORMAL'."""
        q = (
            "判斷以下使用者訊息是否涉及隱私或機密內容（例如：金融帳戶、錢包、私鑰、密碼、"
            "個資、公司內部機密、資安漏洞細節、滲透測試目標）。"
            "只回一個詞：SENSITIVE 或 NORMAL。\n\n訊息：" + (text or "")
        )
        try:
            ans = await self.generate(q)
            return "SENSITIVE" if "SENSITIVE" in ans.upper() else "NORMAL"
        except Exception:
            return "NORMAL"

    async def stream(self, prompt: str):
        # Gemini is fast enough; emulate streaming by yielding the whole reply once.
        text = await self.generate(prompt)
        yield text


def _make_backend(local_llm: Any, model: Optional[str]):
    backend = os.environ.get("ELIANA_LLM_BACKEND", "local").strip().lower()
    if backend == "gemini":
        key = os.environ.get("ELIANA_GEMINI__API_KEY", "").strip()
        gmodel = os.environ.get("ELIANA_GEMINI__MODEL", "gemini-2.5-flash").strip()
        if key:
            logger.info("llm_backend_selected", backend="gemini", model=gmodel)
            return _GeminiBackend(key, gmodel)
        logger.warning("gemini_backend_requested_but_no_key; falling back to local")
    logger.info("llm_backend_selected", backend="local", model=model)
    return _OllamaBackend(local_llm, model) if local_llm is not None else None


# --------------------------------------------------------------------------- #
# Layer-1 routing: hard rules (sensitive -> local, else cloud) + manual override
# --------------------------------------------------------------------------- #
_SENSITIVE_KEYWORDS = (
    "錢包", "wallet", "私鑰", "private key", "助記詞", "seed phrase",
    "密碼", "password", "token", "金鑰", "api key", "api_key",
    "掃描", "scan", "漏洞", "vulnerability", "exploit", "payload",
    "bounty", "滲透", "pentest", "機密", "confidential", "secret",
)


def _looks_sensitive(text: str) -> bool:
    low = (text or "").lower()
    return any(kw.lower() in low for kw in _SENSITIVE_KEYWORDS)


def _route_backend(text: str, force: str | None) -> str:
    """Layer 1 hard rules. Returns 'local' or 'cloud'.

    force: 'local'/'cloud' from a /local or /cloud command (highest priority).
    Sensitive content is pinned to local (privacy red line, never gambled on an LLM).
    Default is cloud (Gemini) for speed/quality.
    """
    if force in ("local", "cloud"):
        return force
    if _looks_sensitive(text):
        return "local"
    return "cloud"


class _DefaultDenyAuthGate:
    async def request(self, description: str, risk_level: str = "low") -> dict:
        logger.info("personality_auth_default_deny", description=description)
        return {"authorized": False, "reason": "no authorization gate wired (default deny)"}


class _OllamaClientForEngine:
    """Adapts the active backend to personality's OllamaClient Protocol."""
    def __init__(self, backend) -> None:
        self._backend = backend

    async def generate(self, prompt: str, **kwargs: Any) -> str:
        if self._backend is None:
            return ""
        return await self._backend.generate(prompt)


class PersonalityAdapter:
    """Implements subsystems.PersonalityPort with a pluggable LLM backend."""

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
        # Dual backends for layered routing
        self._local_backend = _OllamaBackend(local_llm, model) if local_llm is not None else None
        self._cloud_backend = None
        _key = os.environ.get("ELIANA_GEMINI__API_KEY", "").strip()
        if _key:
            _gm = os.environ.get("ELIANA_GEMINI__MODEL", "gemini-2.5-flash").strip()
            self._cloud_backend = _GeminiBackend(_key, _gm)
        # default backend for engine wiring (prefer cloud if available)
        self._backend = self._cloud_backend or self._local_backend
        self.force_mode = None  # None | 'local' | 'cloud' (set via /local /cloud)
        self._history = {}
        self._history_max = 6
        self._components = None
        self._db = None
        self._init_lock: Optional[asyncio.Lock] = None

    async def _ensure_components(self):
        if self._components is not None:
            return self._components
        if self._backend is None:
            return None
        if self._init_lock is None:
            self._init_lock = asyncio.Lock()
        async with self._init_lock:
            if self._components is None:
                try:
                    from app.personality.app_factory import build_components
                    components, db = await build_components(
                        profile_dir=self._profile_dir,
                        llm_client=_OllamaClientForEngine(self._backend),
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

    def _active_profile(self):
        comps = self._components
        if comps is None:
            return None
        engine = getattr(comps, "engine", None)
        if engine is not None and hasattr(engine, "get_active_profile"):
            try:
                return engine.get_active_profile()
            except Exception:
                return None
        return None

    def _get_history(self, key):
        if not key:
            return []
        return self._history.get(key, [])

    def _record(self, key, user_text, assistant_text):
        if not key:
            return
        lst = self._history.setdefault(key, [])
        lst.append({"user": user_text, "assistant": assistant_text})
        if len(lst) > self._history_max:
            del lst[: len(lst) - self._history_max]

    async def _pick(self, text: str):
        """Layered routing. Returns (backend, label).

        Layer 1 (hard rules): manual force + obvious sensitive keywords -> local.
        Layer 2 (smart): if auto and layer-1 said cloud, let Gemini classify; if it
                 judges SENSITIVE, reroute to local. Keeps privacy for the fuzzy cases
                 the keyword list missed, with near-zero latency for normal chat.
        """
        choice = _route_backend(text, self.force_mode)
        # Layer 2: only when auto-mode, not already sensitive, and both backends exist
        if (self.force_mode is None and choice == "cloud"
                and self._cloud_backend is not None and self._local_backend is not None):
            try:
                verdict = await self._cloud_backend.classify(text)
                if verdict == "SENSITIVE":
                    logger.info("layer2_reroute_local", reason="gemini_classified_sensitive")
                    return self._local_backend, "local"
            except Exception as exc:  # noqa: BLE001
                logger.warning("layer2_classify_failed", error=str(exc))
        if choice == "local":
            b = self._local_backend or self._cloud_backend
            return b, ("local" if self._local_backend else "cloud")
        b = self._cloud_backend or self._local_backend
        return b, ("cloud" if self._cloud_backend else "local")

    async def generate_reply(self, context: dict) -> str:
        prompt = str(context.get("prompt") or context.get("text") or "")
        hkey = context.get("history_key")
        await self._ensure_components()
        backend, label = await self._pick(prompt)
        if backend is None:
            raise SubsystemNotWired("no LLM backend available")
        full = _build_persona_prompt(self._active_profile(), prompt, self._get_history(hkey))
        try:
            logger.info("route_decision", backend=label, sensitive=_looks_sensitive(prompt))
            reply = await backend.generate(full)
        except Exception as exc:  # noqa: BLE001
            if label == "cloud" and self._local_backend is not None:
                logger.warning("cloud_failed_fallback_local", error=str(exc))
                reply = await self._local_backend.generate(full)
            else:
                raise
        self._record(hkey, prompt, reply)
        return reply

    async def generate_reply_stream(self, context: dict):
        prompt = str(context.get("prompt") or context.get("text") or "")
        hkey = context.get("history_key")
        await self._ensure_components()
        backend, label = await self._pick(prompt)
        if backend is None:
            yield "(no LLM backend)"
            return
        full = _build_persona_prompt(self._active_profile(), prompt, self._get_history(hkey))
        logger.info("route_decision", backend=label, sensitive=_looks_sensitive(prompt))
        yield f"__BACKEND__:{label}"
        _acc = []
        try:
            async for chunk in backend.stream(full):
                _acc.append(chunk)
                yield chunk
            self._record(hkey, prompt, "".join(_acc).strip())
        except Exception as exc:  # noqa: BLE001
            if label == "cloud" and self._local_backend is not None:
                logger.warning("cloud_stream_failed_fallback_local", error=str(exc))
                try:
                    async for chunk in self._local_backend.stream(full):
                        yield chunk
                    return
                except Exception as exc2:  # noqa: BLE001
                    yield f"(error: {exc2})"
            else:
                yield f"(error: {exc})"

    async def observe_conversation(self, conversation: dict) -> None:
        comps = await self._ensure_components()
        if comps is None:
            return
        analyzer = getattr(comps, "analyzer", None)
        if analyzer is None or not hasattr(analyzer, "analyze_conversation"):
            return
        try:
            await analyzer.analyze_conversation(conversation)
        except Exception as exc:  # noqa: BLE001
            logger.warning("personality_observe_failed", error=str(exc))

    async def health(self) -> dict:
        return {"subsystem": "personality",
                "wired": self._components is not None,
                "backend": os.environ.get("ELIANA_LLM_BACKEND", "local")}