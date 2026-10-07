"""LLM 推論相關資料模型."""

from dataclasses import dataclass


@dataclass
class LLMResponse:
    """LLM 推論回應。"""
    text: str = ""
    model: str = ""
    tokens_generated: int = 0
    generation_time_ms: float = 0.0


@dataclass
class ModelInfo:
    """模型資訊。"""
    name: str = ""
    size_gb: float = 0.0
    quantization: str = "Q4_K_M"
    loaded: bool = False
