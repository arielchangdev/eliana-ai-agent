"""Material_Processor：教材處理主元件。

將原始文本/檔案解析為結構化 KnowledgeFragment：
偵測格式 → 解析 → 切分 → 嵌入 → 分類 → 寫入向量庫。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..interfaces import Classifier, Embedder, VectorStoreProtocol
from ..models import (
    EMBEDDING_DIM,
    CategoryTag,
    KnowledgeFragment,
    ProcessResult,
    SourceMeta,
    SourceType,
    UploadMeta,
)
from .chunker import chunk_text
from .parsers.dispatcher import (
    EmptyContentError,
    PdfParseError,
    UnsupportedFormatError,
    parse_file,
    parse_text_content,
)
from .parsers.format_detector import detect_format
from .tokenizer import count_tokens

# 嵌入失敗時的重試次數
_EMBED_RETRIES = 2
# 預設分類標籤（分類器未回傳任何標籤時）
_DEFAULT_TAG = CategoryTag.ATTACK_TECHNIQUE


class MaterialProcessor:
    def __init__(
        self,
        embedder: Embedder,
        vector_store: VectorStoreProtocol,
        classifier: Optional[Classifier] = None,
        min_tokens: int = 256,
        max_tokens: int = 1024,
    ):
        self.embedder = embedder
        self.vector_store = vector_store
        self.classifier = classifier
        self.min_tokens = min_tokens
        self.max_tokens = max_tokens

    # ----- 對外入口 ------------------------------------------------------- #
    async def process_file(
        self, file_path: str | Path, meta: UploadMeta
    ) -> ProcessResult:
        """處理使用者上傳檔案。"""
        path = Path(file_path)
        try:
            text, _fmt = parse_file(path)
        except UnsupportedFormatError as exc:
            return _rejected(str(exc))
        except PdfParseError as exc:
            return _rejected(str(exc))
        except EmptyContentError as exc:
            return _rejected(str(exc))
        except FileNotFoundError:
            return _rejected(f"檔案不存在: {path}")
        except OSError as exc:
            return _rejected(f"檔案讀取失敗: {exc}")

        source_meta = SourceMeta(
            source_type=meta.source_type,
            source_url=meta.filename,
            category_tags=meta.category_tags,
        )
        return await self._build_and_store(text, source_meta)

    async def process_text(
        self, text: str, source_meta: SourceMeta
    ) -> ProcessResult:
        """處理純文字（供爬蟲使用）。"""
        if text is None or not text.strip():
            return _rejected("內容為空")
        return await self._build_and_store(text, source_meta)

    def detect_format(self, file_path: str | Path):
        """依副檔名偵測格式（委派給 format_detector）。"""
        return detect_format(file_path)

    def chunk_text(self, text: str, min_tokens: int | None = None,
                   max_tokens: int | None = None):
        return chunk_text(
            text,
            min_tokens=min_tokens or self.min_tokens,
            max_tokens=max_tokens or self.max_tokens,
        )

    # ----- 內部流程 ------------------------------------------------------- #
    async def _build_and_store(
        self, text: str, source_meta: SourceMeta
    ) -> ProcessResult:
        chunks = chunk_text(text, self.min_tokens, self.max_tokens)
        if not chunks:
            return _rejected("內容為空")

        errors: list[str] = []
        fragments: list[KnowledgeFragment] = []
        category_distribution: dict[str, int] = {}
        total_tokens = 0

        for chunk in chunks:
            # 生成嵌入向量（含重試）
            embedding = await self._embed_with_retry(chunk.text, errors)
            if embedding is None:
                continue  # 跳過該片段，錯誤已記錄

            # 指派分類標籤
            tags = await self._classify(chunk.text, source_meta.category_tags)

            fragment = KnowledgeFragment(
                id=str(uuid.uuid4()),
                text=chunk.text,
                embedding=embedding,
                source_type=source_meta.source_type,
                source_url=source_meta.source_url,
                category_tags=tags,
                created_at=datetime.now(timezone.utc),
                token_count=chunk.token_count,
            )
            fragments.append(fragment)
            total_tokens += chunk.token_count
            for tag in tags:
                category_distribution[tag.value] = (
                    category_distribution.get(tag.value, 0) + 1
                )

        if fragments:
            try:
                await self.vector_store.upsert_fragments(fragments)
            except Exception as exc:  # 向量庫寫入失敗
                errors.append(f"向量庫寫入失敗: {exc}")
                return ProcessResult(
                    fragments_created=0,
                    total_tokens=0,
                    category_distribution={},
                    errors=errors,
                )

        return ProcessResult(
            fragments_created=len(fragments),
            total_tokens=total_tokens,
            category_distribution=category_distribution,
            errors=errors,
        )

    async def _embed_with_retry(
        self, text: str, errors: list[str]
    ) -> Optional[list[float]]:
        last_exc: Optional[Exception] = None
        for _attempt in range(_EMBED_RETRIES + 1):
            try:
                vectors = await self.embedder.embed([text])
                if not vectors or not vectors[0]:
                    raise ValueError("嵌入結果為空")
                vec = list(vectors[0])
                if len(vec) != EMBEDDING_DIM:
                    raise ValueError(
                        f"嵌入維度錯誤: 期望 {EMBEDDING_DIM}, 實際 {len(vec)}"
                    )
                return vec
            except Exception as exc:  # noqa: BLE001 - 重試所有例外
                last_exc = exc
        errors.append(f"嵌入失敗，已跳過片段: {last_exc}")
        return None

    async def _classify(
        self, text: str, fallback_tags: list[CategoryTag]
    ) -> list[CategoryTag]:
        if self.classifier is not None:
            try:
                tags = await self.classifier.classify(text)
                if tags:
                    return tags
            except Exception:  # noqa: BLE001 - 分類失敗退回預設
                pass
        if fallback_tags:
            return list(fallback_tags)
        return [_DEFAULT_TAG]


def _rejected(message: str) -> ProcessResult:
    """建立拒絕處理的結果。"""
    return ProcessResult(
        fragments_created=0,
        total_tokens=0,
        category_distribution={},
        errors=[message],
    )
