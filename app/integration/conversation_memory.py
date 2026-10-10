"""Long-term conversation memory via local ChromaDB + Ollama embeddings.

Stores each conversation turn as a vector so Eliana can recall semantically
relevant past exchanges across sessions (survives restarts). Fully local:
- storage: Chroma PersistentClient (on-disk, no server needed)
- embeddings: Ollama nomic-embed-text (on-box, no cloud, privacy-preserving)

Independent module; does not touch learning-engine's VectorStore.
"""
from __future__ import annotations

import json
import time
import urllib.request
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)

_OLLAMA_BASE = "http://127.0.0.1:11434"
_EMBED_MODEL = "nomic-embed-text"


def _embed(text: str) -> Optional[list]:
    """Get an embedding vector from Ollama. Returns None on failure."""
    try:
        payload = json.dumps({"model": _EMBED_MODEL, "prompt": text}).encode()
        req = urllib.request.Request(
            f"{_OLLAMA_BASE}/api/embeddings", data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
        emb = data.get("embedding")
        return emb if emb else None
    except Exception as exc:  # noqa: BLE001
        logger.warning("embed_failed", error=str(exc))
        return None


class ConversationMemory:
    """Per-user long-term memory backed by a local Chroma collection."""

    def __init__(self, persist_dir: str = "data/eliana_memory") -> None:
        self._persist_dir = persist_dir
        self._client = None
        self._collection = None

    def _ensure(self):
        if self._collection is not None:
            return self._collection
        try:
            import chromadb
            self._client = chromadb.PersistentClient(path=self._persist_dir)
            # cosine space; we supply our own embeddings
            self._collection = self._client.get_or_create_collection(
                name="eliana_conversations",
                metadata={"hnsw:space": "cosine"},
            )
            logger.info("memory_collection_ready", path=self._persist_dir)
        except Exception as exc:  # noqa: BLE001
            logger.warning("memory_init_failed", error=str(exc))
            self._collection = None
        return self._collection

    def remember(self, key: str, user_text: str, assistant_text: str) -> None:
        """Store one conversation turn as a vector (keyed by user)."""
        col = self._ensure()
        if col is None:
            return
        doc = f"Ariel: {user_text}\nEliana: {assistant_text}"
        emb = _embed(doc)
        if emb is None:
            return
        try:
            doc_id = f"{key}-{int(time.time()*1000)}"
            col.add(
                ids=[doc_id],
                embeddings=[emb],
                documents=[doc],
                metadatas=[{"key": str(key), "ts": time.time()}],
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("memory_add_failed", error=str(exc))

    def recall(self, key: str, query: str, k: int = 3) -> list:
        """Return up to k past turns most relevant to query (for this user)."""
        col = self._ensure()
        if col is None:
            return []
        emb = _embed(query)
        if emb is None:
            return []
        try:
            res = col.query(
                query_embeddings=[emb],
                n_results=k,
                where={"key": str(key)},
            )
            docs = (res.get("documents") or [[]])[0]
            return docs
        except Exception as exc:  # noqa: BLE001
            logger.warning("memory_recall_failed", error=str(exc))
            return []

    def count(self, key: Optional[str] = None) -> int:
        col = self._ensure()
        if col is None:
            return 0
        try:
            if key is None:
                return col.count()
            return len(col.get(where={"key": str(key)}).get("ids", []))
        except Exception:
            return 0