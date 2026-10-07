"""外部依賴的抽象介面（Protocol）。

以 Protocol 定義注入式介面，讓核心元件不直接相依 Ollama /
Authorization_Gate / Learning_Engine 的具體實作，便於測試以 mock 替代。
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class OllamaClient(Protocol):
    """Local_LLM 推論介面（來自 eliana-core-infra）。"""

    async def generate(self, prompt: str, **kwargs: Any) -> str:
        """執行本地推論，回傳生成文字。"""
        ...


@runtime_checkable
class LearningEngineClient(Protocol):
    """學習引擎回饋介面（來自 eliana-learning-engine）。"""

    async def submit_patterns(self, patterns: list[dict]) -> None:
        """提交有價值的溝通模式供學習。"""
        ...


@runtime_checkable
class AuthorizationGateClient(Protocol):
    """授權閘門介面（來自 eliana-bounty-hunter）。"""

    async def request(self, description: str, risk_level: str = "low") -> dict:
        """請求授權，回傳 {"authorized": bool, "reason": str}。

        不可達時實作應拋出例外，由呼叫端安全降級為拒絕。
        """
        ...
