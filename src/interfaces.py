"""外部依賴的抽象介面（Protocol）。

以 Protocol 定義注入式介面，讓核心元件不直接相依 Ollama / ChromaDB 的
具體實作，便於測試以 mock 替代。
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import CategoryTag, KnowledgeFragment, SearchFilters, SearchResult


@runtime_checkable
class Embedder(Protocol):
    """嵌入向量生成器（sentence-transformers / Local_LLM）。"""

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """回傳每段文字的 384 維嵌入向量。"""
        ...


@runtime_checkable
class Classifier(Protocol):
    """分類標籤指派器（Local_LLM）。"""

    async def classify(self, text: str) -> list[CategoryTag]:
        """為文字指派至少一個 CategoryTag。"""
        ...


@runtime_checkable
class Summarizer(Protocol):
    """摘要與關鍵資訊擷取（Local_LLM）。"""

    async def summarize(self, text: str) -> str:
        """回傳文字摘要（漏洞類型、影響範圍、攻擊向量、修復方式）。"""
        ...


@runtime_checkable
class VectorStoreProtocol(Protocol):
    """向量庫最小介面，供 Material_Processor 寫入使用。"""

    async def upsert_fragments(self, fragments: list[KnowledgeFragment]):
        ...

    async def search(
        self, query: str, top_k: int = 10, filters: SearchFilters | None = None
    ) -> list[SearchResult]:
        ...
