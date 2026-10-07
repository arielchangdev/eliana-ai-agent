"""去重模組：以 cosine similarity 判定重複片段。

去重規則（design.md）：新片段以其 embedding 對現有庫做 top-1 搜尋，
cosine similarity > 0.95 判定為重複。
"""
from __future__ import annotations

import math
from typing import Optional

from ..models import DedupResult

DEFAULT_THRESHOLD = 0.95


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """計算兩向量的 cosine similarity；零向量回傳 0.0。"""
    if len(a) != len(b):
        raise ValueError("向量維度不一致")
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (math.sqrt(na) * math.sqrt(nb))


class Deduplicator:
    """對一組既有 (fragment_id, embedding) 進行去重判定。"""

    def __init__(self, threshold: float = DEFAULT_THRESHOLD):
        self.threshold = threshold

    def check(
        self,
        embedding: list[float],
        existing: list[tuple[str, list[float]]],
    ) -> DedupResult:
        """對 existing 做 top-1 搜尋，> threshold 判定為重複。

        參數 existing 為 (fragment_id, embedding) 序列。
        """
        best_id: Optional[str] = None
        best_sim = -1.0
        for frag_id, emb in existing:
            sim = cosine_similarity(embedding, emb)
            if sim > best_sim:
                best_sim = sim
                best_id = frag_id

        if best_id is not None and best_sim > self.threshold:
            return DedupResult(
                is_duplicate=True,
                matched_fragment_id=best_id,
                similarity=best_sim,
            )
        return DedupResult(
            is_duplicate=False,
            matched_fragment_id=None,
            similarity=max(best_sim, 0.0) if best_id is not None else 0.0,
        )


def is_duplicate(
    sim: float, threshold: float = DEFAULT_THRESHOLD
) -> bool:
    """純函式：相似度 > threshold 即為重複。"""
    return sim > threshold
