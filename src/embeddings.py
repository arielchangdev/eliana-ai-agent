"""具體嵌入器實作（sentence-transformers）。

提供符合 ``interfaces.Embedder`` 協定的真實嵌入器，使用
all-MiniLM-L6-v2（384 維）。模型於首次呼叫時 lazy load，
避免匯入即載入造成啟動延遲。
"""
from __future__ import annotations

import asyncio
from typing import Optional

from .models import EMBEDDING_DIM


class SentenceTransformerEmbedder:
    """以 sentence-transformers 產生 384 維嵌入向量。"""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self._model: Optional[object] = None

    def _ensure_model(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self.model_name)
        return self._model

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """回傳每段文字的嵌入向量（於執行緒中執行避免阻塞事件迴圈）。"""
        model = await asyncio.to_thread(self._ensure_model)

        def _encode() -> list[list[float]]:
            vectors = model.encode(
                texts, convert_to_numpy=True, normalize_embeddings=True
            )
            return [v.astype(float).tolist() for v in vectors]

        result = await asyncio.to_thread(_encode)
        # 維度驗證：確保與設計一致（384 維）
        for vec in result:
            if len(vec) != EMBEDDING_DIM:
                raise ValueError(
                    f"嵌入維度錯誤: 期望 {EMBEDDING_DIM}, 實際 {len(vec)}"
                )
        return result
