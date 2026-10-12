"""知識庫寫入（/learn 用）：把「Ariel 明確教的知識」存進知識庫 collection。

與對話記憶（conversation_memory，eliana_conversations）刻意分開：
- 這裡存的是「你教的」知識，寫進 ariel_knowledge collection，面板「你教的」
  計數讀的就是這個。
- 存知識 **不走對話生成、不帶對話歷史、不觸發人格演化**——這正是把「教它」
  和「跟它聊」分流的重點。

全本地、$0，比照 conversation_memory 的可運作模式：
- storage: Chroma PersistentClient（on-disk）
- embeddings: Ollama nomic-embed-text（on-box）

persist_dir 應指向面板知識庫同一處，由 ELIANA_KNOWLEDGE__DIR 提供（在 VM 上
設為實際路徑）；未設時退回 YOUR_CHROMA_DIR 佔位符；collection 預設 ariel_knowledge。
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)

_OLLAMA_BASE = "http://127.0.0.1:11434"
_EMBED_MODEL = "nomic-embed-text"


def _embed(text: str) -> Optional[list]:
    try:
        payload = json.dumps({"model": _EMBED_MODEL, "prompt": text}).encode()
        req = urllib.request.Request(
            f"{_OLLAMA_BASE}/api/embeddings", data=payload,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
        emb = data.get("embedding")
        return emb if emb else None
    except Exception as exc:  # noqa: BLE001
        logger.warning("knowledge_embed_failed", error=str(exc))
        return None


class KnowledgeStore:
    """把使用者教的知識寫進知識庫（面板「你教的」）。"""

    def __init__(self, persist_dir: Optional[str] = None,
                 collection: str = "ariel_knowledge") -> None:
        # 寫進面板知識庫同一個 persist dir，/learn 才會反映在面板計數上。
        # 實際路徑由 ELIANA_KNOWLEDGE__DIR 提供（去識別化：repo 不寫死主機路徑）。
        self._persist_dir = (persist_dir
                             or os.environ.get("ELIANA_KNOWLEDGE__DIR")
                             or "YOUR_CHROMA_DIR")
        self._collection_name = collection
        self._collection = None

    def _ensure(self):
        if self._collection is not None:
            return self._collection
        try:
            import chromadb
            client = chromadb.PersistentClient(path=self._persist_dir)
            self._collection = client.get_or_create_collection(
                name=self._collection_name,
                metadata={"hnsw:space": "cosine"})
        except Exception as exc:  # noqa: BLE001
            logger.warning("knowledge_store_init_failed", error=str(exc))
            self._collection = None
        return self._collection

    def learn(self, text: str, source: str = "telegram") -> bool:
        """存一條知識。成功回 True，embedding/chroma 失敗回 False（誠實）。"""
        text = (text or "").strip()
        if not text:
            return False
        col = self._ensure()
        if col is None:
            return False
        emb = _embed(text)
        if emb is None:
            return False
        try:
            doc_id = f"learn-{int(time.time()*1000)}"
            col.add(
                ids=[doc_id], embeddings=[emb], documents=[text],
                metadatas=[{"source": source, "ts": time.time(),
                            "taught": True}])
            logger.info("knowledge_learned", chars=len(text), source=source)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("knowledge_add_failed", error=str(exc))
            return False

    def count(self) -> int:
        col = self._ensure()
        if col is None:
            return 0
        try:
            return col.count()
        except Exception:
            return 0
