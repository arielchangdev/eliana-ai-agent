"""Pydantic v2 資料模型。

人格設定、演化建議、版本歷史等核心模型。所有時間戳使用 UTC。
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal, Union
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ToneStyle(str, Enum):
    FORMAL = "formal"
    CASUAL = "casual"
    TECHNICAL = "technical"
    FRIENDLY = "friendly"
    WITTY = "witty"
    ASSERTIVE = "assertive"


class CommunicationPreferences(BaseModel):
    response_length: Literal["concise", "moderate", "detailed"] = "moderate"
    emoji_frequency: float = Field(ge=0.0, le=1.0, default=0.3)
    technical_depth: Literal["shallow", "moderate", "deep"] = "deep"


class ResponseStrategy(BaseModel):
    proactiveness: float = Field(ge=0.0, le=1.0, default=0.6)
    humor_ratio: float = Field(ge=0.0, le=1.0, default=0.2)
    citation_preference: Literal["minimal", "moderate", "heavy"] = "moderate"


class PersonalityProfile(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    version: int = 1
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    # 核心人格
    tone_styles: list[ToneStyle] = Field(min_length=1, max_length=6)
    communication: CommunicationPreferences = Field(
        default_factory=CommunicationPreferences
    )
    expertise_tags: list[str] = Field(default_factory=list, max_length=50)
    interest_tags: list[str] = Field(default_factory=list, max_length=50)
    response_strategy: ResponseStrategy = Field(default_factory=ResponseStrategy)

    # 元資料
    name: str = "Eliana"
    description: str = ""

    def detect_conflicts(self) -> list[str]:
        """檢測已知衝突模式，回傳衝突訊息清單（可能為空）。"""
        conflicts: list[str] = []
        if (
            ToneStyle.FORMAL in self.tone_styles
            and self.communication.emoji_frequency > 0.7
        ):
            conflicts.append("formal 語氣與高表情符號頻率衝突")
        if (
            self.communication.response_length == "concise"
            and self.response_strategy.citation_preference == "heavy"
        ):
            conflicts.append("簡潔回應與大量引用偏好衝突")
        return conflicts


class ParameterChange(BaseModel):
    parameter_path: str  # e.g. "communication.emoji_frequency"
    current_value: Union[float, str]
    suggested_value: Union[float, str]
    change_percent: float = Field(le=5.0, ge=-5.0)  # 單次上限 ±5%
    reason: str = ""

    @field_validator("change_percent")
    @classmethod
    def _clamp_check(cls, v: float) -> float:
        # 硬限制：絕對值不得超過 5.0
        if abs(v) > 5.0:
            raise ValueError(f"change_percent 絕對值不得超過 5.0，收到 {v}")
        return v


class EvolutionSuggestion(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    conversation_id: str
    timestamp: datetime = Field(default_factory=_utcnow)
    changes: list[ParameterChange] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


class VersionEntry(BaseModel):
    id: str
    version_number: int
    change_summary: str
    created_at: datetime
    source: Literal["manual", "evolution", "rollback", "import"]


class ValidationResult(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ThresholdStatus(BaseModel):
    parameter_path: str
    cumulative_percent: float
    threshold: float = 15.0
    exceeded: bool


class AnalysisResult(BaseModel):
    """對話分析結果。"""
    conversation_id: str
    tone_signals: dict[str, float] = Field(default_factory=dict)
    preference_signals: dict[str, float] = Field(default_factory=dict)
    summary: str = ""


class CommunityContext(BaseModel):
    platform: str
    topic: str = ""
    prompt_hint: str = ""


class DraftPost(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    platform: str
    content: str
    interaction_type: Literal["post", "reply"] = "post"


class ApplyResult(BaseModel):
    applied: list[str] = Field(default_factory=list)   # suggestion ids
    pending: list[str] = Field(default_factory=list)
    filtered: list[str] = Field(default_factory=list)  # 被冷卻過濾


class AuthResult(BaseModel):
    authorized: bool
    reason: str = ""


class PublishResult(BaseModel):
    success: bool
    interaction_id: str | None = None
    reason: str = ""
