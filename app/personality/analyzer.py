"""ConversationAnalyzer：使用 Local_LLM 分析對話並提取演化建議。

- analyze_conversation：組 prompt → LLM → 解析為 AnalysisResult
  （30s 逾時；解析失敗重試 1 次後跳過）
- extract_suggestions：計算各參數建議變更，硬限制 change_percent 絕對值 <= 5%
- analyze_community_patterns：分析社群溝通技巧並回饋 Learning_Engine
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional
from uuid import uuid4

from .interfaces import LearningEngineClient, OllamaClient
from .models import (
    AnalysisResult,
    EvolutionSuggestion,
    ParameterChange,
    PersonalityProfile,
)

logger = logging.getLogger(__name__)

_LLM_TIMEOUT = 30.0
_MAX_CHANGE = 5.0  # 單次調整硬上限（百分比）

# 可演化的數值參數路徑與其當前值取得方式
_NUMERIC_PARAMS = {
    "communication.emoji_frequency": lambda p: p.communication.emoji_frequency,
    "response_strategy.proactiveness": lambda p: p.response_strategy.proactiveness,
    "response_strategy.humor_ratio": lambda p: p.response_strategy.humor_ratio,
}


class ConversationAnalyzer:
    def __init__(
        self,
        llm_client: OllamaClient,
        learning_engine: Optional[LearningEngineClient] = None,
    ):
        self.llm = llm_client
        self.learning_engine = learning_engine

    # ----- 對話分析 ------------------------------------------------------- #
    async def analyze_conversation(
        self, conversation: list[dict], conversation_id: Optional[str] = None
    ) -> Optional[AnalysisResult]:
        """分析對話，回傳 AnalysisResult；失敗（逾時/解析錯）回傳 None。"""
        conv_id = conversation_id or str(uuid4())
        prompt = self._build_prompt(conversation)

        # 逾時 + 重試 1 次
        for attempt in range(2):
            try:
                raw = await asyncio.wait_for(
                    self.llm.generate(prompt), timeout=_LLM_TIMEOUT
                )
            except asyncio.TimeoutError:
                logger.warning("LLM 分析逾時（attempt %d），跳過", attempt + 1)
                return None
            except Exception as exc:  # noqa: BLE001
                logger.warning("LLM 呼叫失敗（attempt %d）: %s", attempt + 1, exc)
                if attempt == 0:
                    continue
                return None

            parsed = self._parse_response(raw, conv_id)
            if parsed is not None:
                return parsed
            logger.warning("LLM 回應解析失敗（attempt %d）", attempt + 1)
        return None

    def _build_prompt(self, conversation: list[dict]) -> str:
        lines = ["分析以下對話的用詞偏好與語氣模式，回傳 JSON："]
        for turn in conversation:
            role = turn.get("role", "user")
            content = turn.get("content", "")
            lines.append(f"[{role}] {content}")
        lines.append(
            '請回傳格式：{"tone_signals": {...}, "preference_signals": {...}, '
            '"summary": "..."}'
        )
        return "\n".join(lines)

    def _parse_response(self, raw: str, conv_id: str) -> Optional[AnalysisResult]:
        try:
            data = json.loads(_extract_json(raw))
            return AnalysisResult(
                conversation_id=conv_id,
                tone_signals=_coerce_signal_map(data.get("tone_signals", {})),
                preference_signals=_coerce_signal_map(
                    data.get("preference_signals", {})),
                summary=str(data.get("summary", "")),
            )
        except (json.JSONDecodeError, ValueError, TypeError):
            return None

    # ----- 演化建議提取 --------------------------------------------------- #
    async def extract_suggestions(
        self, analysis: AnalysisResult, current_profile: PersonalityProfile
    ) -> EvolutionSuggestion:
        """從分析結果產生演化建議，change_percent 硬限制絕對值 <= 5%。"""
        changes: list[ParameterChange] = []
        signals = {**analysis.tone_signals, **analysis.preference_signals}

        for path, getter in _NUMERIC_PARAMS.items():
            signal_key = path.split(".")[-1]
            if signal_key not in signals:
                continue
            raw_pct = signals[signal_key]
            # 硬限制：裁切至 [-5, 5]
            pct = _clamp(raw_pct, -_MAX_CHANGE, _MAX_CHANGE)
            current = getter(current_profile)
            suggested = _clamp(current * (1 + pct / 100.0), 0.0, 1.0)
            changes.append(ParameterChange(
                parameter_path=path,
                current_value=current,
                suggested_value=suggested,
                change_percent=pct,
                reason=f"對話分析建議調整 {signal_key}",
            ))

        return EvolutionSuggestion(
            conversation_id=analysis.conversation_id,
            changes=changes,
            confidence=0.6,
        )

    # ----- 社群模式分析 --------------------------------------------------- #
    async def analyze_community_patterns(
        self, posts: list[dict]
    ) -> list[dict]:
        """分析社群貼文溝通技巧，回饋有價值模式至 Learning_Engine。"""
        prompt = "分析以下社群貼文的溝通技巧，萃取有價值模式：\n"
        prompt += "\n".join(p.get("content", "") for p in posts)
        try:
            raw = await asyncio.wait_for(
                self.llm.generate(prompt), timeout=_LLM_TIMEOUT
            )
        except (asyncio.TimeoutError, Exception):  # noqa: BLE001
            return []

        patterns = _safe_parse_patterns(raw)
        if patterns and self.learning_engine is not None:
            try:
                await self.learning_engine.submit_patterns(patterns)
            except Exception:  # noqa: BLE001 - 回饋失敗不影響主流程
                logger.warning("回饋 Learning_Engine 失敗")
        return patterns


# --------------------------------------------------------------------------- #
# helper
# --------------------------------------------------------------------------- #
def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def _strip_code_fence(raw: str) -> str:
    """移除 markdown code fence（```json ... ``` 或 ``` ... ```）。"""
    import re
    text = raw.strip()
    # ```json\n...\n```  或  ```\n...\n```
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return text


def _balanced_json_object(text: str) -> Optional[str]:
    """從第一個 '{' 起，依括號配對找出平衡的 JSON 物件（忽略字串內的括號）。
    比 rfind('}') 穩健：避免抓到後續說明文字裡的 '}' 或多個物件黏在一起。"""
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def _extract_json(raw: str) -> str:
    """從 LLM 回應萃取 JSON 物件，容忍 markdown fence / 前後雜訊 / 尾逗號。"""
    import re
    text = _strip_code_fence(raw or "")
    candidate = _balanced_json_object(text)
    if candidate is None:
        # 退回舊式 find/rfind
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end < start:
            raise ValueError("回應不含 JSON 物件")
        candidate = text[start:end + 1]
    # 清除物件/陣列結尾的尾逗號（小模型常見）：  , }  ->  }
    candidate = re.sub(r",\s*([}\]])", r"\1", candidate)
    return candidate


def _coerce_float(v) -> Optional[float]:
    """容錯把 LLM 的值轉 float。無法轉（如 'high'/null/空）回 None（跳過該鍵）。"""
    if v is None:
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        s = v.strip().rstrip("%").replace("+", "")
        try:
            return float(s)
        except ValueError:
            return None
    return None


def _coerce_signal_map(d) -> dict:
    """把 signal dict 的值容錯轉 float，丟棄無法轉的鍵（不讓一個壞值毀掉整份解析）。"""
    if not isinstance(d, dict):
        return {}
    out = {}
    for k, v in d.items():
        f = _coerce_float(v)
        if f is not None:
            out[str(k)] = f
    return out


def _safe_parse_patterns(raw: str) -> list[dict]:
    try:
        text = raw.strip()
        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end != -1 and end > start:
            return json.loads(text[start:end + 1])
    except (json.JSONDecodeError, ValueError):
        pass
    return []
