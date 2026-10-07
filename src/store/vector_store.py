"""Vector_Store：ChromaDB 向量庫管理（讀寫、去重、歸檔、統計）。

- Collection: ``eliana_knowledge``（cosine distance, 384 維）
- 歸檔 collection: ``eliana_knowledge_archive``
- metadata 以純量儲存（category_tags 以 JSON 字串、時間以 ISO 字串）

嵌入向量：
- 片段 embedding 由 KnowledgeFragment 攜帶（呼叫端已生成）。
- search 查詢字串的 embedding 由注入的 embedder 生成。
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from ..interfaces import Embedder
from ..models import (
    ArchiveResult,
    CategoryTag,
    DedupResult,
    KnowledgeFragment,
    SearchFilters,
    SearchResult,
    SourceType,
    UpsertResult,
    VectorStoreStats,
)
from .deduplicator import Deduplicator, cosine_similarity

_COSINE_META = {"hnsw:space": "cosine"}


class VectorStore:
    def __init__(
        self,
        embedder: Embedder,
        persist_dir: Optional[str | Path] = None,
        collection_name: str = "eliana_knowledge",
        archive_collection_name: str = "eliana_knowledge_archive",
        dedup_threshold: float = 0.95,
    ):
        self.embedder = embedder
        self.collection_name = collection_name
        self.archive_collection_name = archive_collection_name
        self.deduplicator = Deduplicator(threshold=dedup_threshold)

        import chromadb

        if persist_dir is None:
            self._client = chromadb.EphemeralClient()
        else:
            Path(persist_dir).mkdir(parents=True, exist_ok=True)
            self._client = chromadb.PersistentClient(path=str(persist_dir))

        self._collection = self._client.get_or_create_collection(
            collection_name, metadata=_COSINE_META
        )
        self._archive = self._client.get_or_create_collection(
            archive_collection_name, metadata=_COSINE_META
        )

    # ----- 寫入與去重 ----------------------------------------------------- #
    async def upsert_fragments(
        self, fragments: list[KnowledgeFragment]
    ) -> UpsertResult:
        """寫入片段，cosine > threshold 者合併而非新增。"""
        inserted = 0
        merged = 0
        errors: list[str] = []

        for frag in fragments:
            try:
                dedup = await self.deduplicate(frag.embedding)
                if dedup.is_duplicate and dedup.matched_fragment_id:
                    await self._merge_into(dedup.matched_fragment_id, frag)
                    merged += 1
                else:
                    await self._insert(frag)
                    inserted += 1
            except Exception as exc:  # noqa: BLE001
                errors.append(f"寫入片段 {frag.id} 失敗: {exc}")

        return UpsertResult(inserted=inserted, merged=merged, errors=errors)

    async def _insert(self, frag: KnowledgeFragment) -> None:
        await asyncio.to_thread(
            self._collection.add,
            ids=[frag.id],
            embeddings=[list(frag.embedding)],
            documents=[frag.text],
            metadatas=[_fragment_to_metadata(frag)],
        )

    async def _merge_into(
        self, existing_id: str, incoming: KnowledgeFragment
    ) -> None:
        """合併：保留較新來源 URL、累加 reference_count。"""
        got = await asyncio.to_thread(
            self._collection.get, ids=[existing_id], include=["metadatas"]
        )
        metas = got.get("metadatas") or []
        if not metas:
            # 既有片段已不存在，直接插入
            await self._insert(incoming)
            return
        meta = dict(metas[0])
        # 累加引用次數
        meta["reference_count"] = int(meta.get("reference_count", 0)) + 1
        # 保留較新來源 URL
        existing_created = _parse_dt(meta.get("created_at"))
        if incoming.created_at and (
            existing_created is None or incoming.created_at >= existing_created
        ):
            if incoming.source_url:
                meta["source_url"] = incoming.source_url
        await asyncio.to_thread(
            self._collection.update, ids=[existing_id], metadatas=[meta]
        )

    async def deduplicate(
        self, embedding: list[float], threshold: Optional[float] = None
    ) -> DedupResult:
        """對現有庫做 top-1 搜尋，回傳是否重複。"""
        thresh = threshold if threshold is not None else self.deduplicator.threshold
        count = await asyncio.to_thread(self._collection.count)
        if count == 0:
            return DedupResult(is_duplicate=False, matched_fragment_id=None, similarity=0.0)

        res = await asyncio.to_thread(
            self._collection.query,
            query_embeddings=[list(embedding)],
            n_results=1,
            include=["distances"],
        )
        ids = res.get("ids") or [[]]
        dists = res.get("distances") or [[]]
        if not ids[0]:
            return DedupResult(is_duplicate=False, matched_fragment_id=None, similarity=0.0)

        # cosine distance = 1 - cosine similarity
        sim = 1.0 - float(dists[0][0])
        if sim > thresh:
            return DedupResult(
                is_duplicate=True, matched_fragment_id=ids[0][0], similarity=sim
            )
        return DedupResult(is_duplicate=False, matched_fragment_id=None, similarity=sim)

    # ----- 檢索 ----------------------------------------------------------- #
    async def search(
        self,
        query: str,
        top_k: int = 10,
        filters: Optional[SearchFilters] = None,
    ) -> list[SearchResult]:
        """語意檢索，套用過濾條件。"""
        vectors = await self.embedder.embed([query])
        query_emb = list(vectors[0])

        where = _filters_to_where(filters)
        count = await asyncio.to_thread(self._collection.count)
        if count == 0:
            return []

        # 為支援日期後過濾，取較多候選
        n = min(max(top_k * 3, top_k), count)
        kwargs: dict[str, Any] = {
            "query_embeddings": [query_emb],
            "n_results": n,
            "include": ["documents", "metadatas", "distances"],
        }
        if where:
            kwargs["where"] = where

        res = await asyncio.to_thread(self._collection.query, **kwargs)
        return self._rows_to_results(res, filters, top_k)

    def _rows_to_results(
        self, res: dict, filters: Optional[SearchFilters], top_k: int
    ) -> list[SearchResult]:
        ids = (res.get("ids") or [[]])[0]
        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]

        results: list[SearchResult] = []
        for i, frag_id in enumerate(ids):
            meta = metas[i] if i < len(metas) else {}
            frag = _metadata_to_fragment(frag_id, docs[i] if i < len(docs) else "", meta)
            # 日期範圍後過濾（Chroma where 不易表達 ISO 字串範圍）
            if not _passes_date_filter(frag, filters):
                continue
            score = 1.0 - float(dists[i]) if i < len(dists) else 0.0
            results.append(SearchResult(fragment=frag, score=score))
            if len(results) >= top_k:
                break
        return results

    # ----- 歸檔 ----------------------------------------------------------- #
    async def archive_stale(
        self, days: int = 180, reference_time: Optional[datetime] = None
    ) -> ArchiveResult:
        """將 last_referenced_at 超過 days 天未引用的片段移至歸檔區。

        未曾被引用（last_referenced_at 為空）者，以 created_at 判斷。
        reference_time 供測試傳入固定基準時間；預設為現在。
        """
        base = reference_time or datetime.now(timezone.utc)
        cutoff = base - timedelta(days=days)
        got = await asyncio.to_thread(
            self._collection.get, include=["documents", "metadatas", "embeddings"]
        )
        ids = got.get("ids") or []
        docs = got.get("documents") or []
        metas = got.get("metadatas") or []
        embs = got.get("embeddings")
        embs = list(embs) if embs is not None else []

        to_archive_ids: list[str] = []
        arc_docs: list[str] = []
        arc_metas: list[dict] = []
        arc_embs: list[list[float]] = []

        for i, frag_id in enumerate(ids):
            meta = metas[i] if i < len(metas) else {}
            ref_dt = _parse_dt(meta.get("last_referenced_at"))
            basis = ref_dt or _parse_dt(meta.get("created_at"))
            if basis is not None and basis < cutoff:
                to_archive_ids.append(frag_id)
                arc_docs.append(docs[i] if i < len(docs) else "")
                arc_metas.append(dict(meta))
                if i < len(embs):
                    arc_embs.append(list(embs[i]))

        errors: list[str] = []
        if to_archive_ids:
            try:
                add_kwargs: dict[str, Any] = {
                    "ids": to_archive_ids,
                    "documents": arc_docs,
                    "metadatas": arc_metas,
                }
                if len(arc_embs) == len(to_archive_ids):
                    add_kwargs["embeddings"] = arc_embs
                await asyncio.to_thread(self._archive.add, **add_kwargs)
                await asyncio.to_thread(self._collection.delete, ids=to_archive_ids)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"歸檔失敗: {exc}")

        remaining = await asyncio.to_thread(self._collection.count)
        return ArchiveResult(
            archived=len(to_archive_ids), remaining=remaining, errors=errors
        )

    # ----- 統計 ----------------------------------------------------------- #
    async def get_stats(self) -> VectorStoreStats:
        got = await asyncio.to_thread(self._collection.get, include=["metadatas"])
        metas = got.get("metadatas") or []
        category_dist: dict[str, int] = {}
        source_dist: dict[str, int] = {}
        for meta in metas:
            for tag in json.loads(meta.get("category_tags", "[]")):
                category_dist[tag] = category_dist.get(tag, 0) + 1
            st = meta.get("source_type", "unknown")
            source_dist[st] = source_dist.get(st, 0) + 1
        return VectorStoreStats(
            total_fragments=len(metas),
            category_distribution=category_dist,
            source_distribution=source_dist,
        )

    async def count(self) -> int:
        return await asyncio.to_thread(self._collection.count)

    async def archive_count(self) -> int:
        return await asyncio.to_thread(self._archive.count)


# --------------------------------------------------------------------------- #
# metadata 轉換工具
# --------------------------------------------------------------------------- #
def _fragment_to_metadata(frag: KnowledgeFragment) -> dict[str, Any]:
    return {
        "source_type": frag.source_type.value
        if isinstance(frag.source_type, SourceType)
        else str(frag.source_type),
        "source_url": frag.source_url or "",
        "category_tags": json.dumps(
            [t.value if isinstance(t, CategoryTag) else str(t) for t in frag.category_tags]
        ),
        "created_at": frag.created_at.isoformat() if frag.created_at else "",
        "last_referenced_at": frag.last_referenced_at.isoformat()
        if frag.last_referenced_at
        else "",
        "reference_count": int(frag.reference_count),
        "token_count": int(frag.token_count),
    }


def _metadata_to_fragment(
    frag_id: str, document: str, meta: dict[str, Any]
) -> KnowledgeFragment:
    tags: list[CategoryTag] = []
    for t in json.loads(meta.get("category_tags", "[]")):
        try:
            tags.append(CategoryTag(t))
        except ValueError:
            pass
    try:
        source_type = SourceType(meta.get("source_type", ""))
    except ValueError:
        source_type = SourceType.USER_UPLOAD
    return KnowledgeFragment(
        id=frag_id,
        text=document,
        embedding=[],  # 檢索結果不回傳 embedding（節省頻寬）
        source_type=source_type,
        source_url=meta.get("source_url") or None,
        category_tags=tags,
        created_at=_parse_dt(meta.get("created_at")) or datetime.now(timezone.utc),
        last_referenced_at=_parse_dt(meta.get("last_referenced_at")),
        reference_count=int(meta.get("reference_count", 0)),
        token_count=int(meta.get("token_count", 0)),
    )


def _filters_to_where(filters: Optional[SearchFilters]) -> Optional[dict]:
    """將 SearchFilters 的 source_types 轉為 Chroma where。

    category_tags 因以 JSON 字串儲存，無法用 Chroma where 精確比對，
    改於檢索後過濾（見 _passes_date_filter 之外的後過濾邏輯）。
    這裡僅處理 source_types。
    """
    if filters is None:
        return None
    conditions: list[dict] = []
    if filters.source_types:
        vals = [
            s.value if isinstance(s, SourceType) else str(s)
            for s in filters.source_types
        ]
        conditions.append({"source_type": {"$in": vals}})
    if not conditions:
        return None
    if len(conditions) == 1:
        return conditions[0]
    return {"$and": conditions}


def _passes_date_filter(
    frag: KnowledgeFragment, filters: Optional[SearchFilters]
) -> bool:
    """檢查片段是否通過 date_range 與 category_tags 後過濾。"""
    if filters is None:
        return True
    # category_tags：需包含所有指定標籤中的至少一個（交集）
    if filters.category_tags:
        wanted = set(filters.category_tags)
        if not wanted.intersection(set(frag.category_tags)):
            return False
    if filters.source_types:
        if frag.source_type not in set(filters.source_types):
            return False
    created = frag.created_at
    if filters.date_from and created and created < filters.date_from:
        return False
    if filters.date_to and created and created > filters.date_to:
        return False
    return True


def _parse_dt(value: Any) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
