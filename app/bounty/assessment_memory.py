"""評估經驗記憶（成長閉環的「存 + 回想」半）。

把「已授權掃描的既有評估結果」轉成可累積、可回想的經驗，讓 Eliana 越評估
越懂判斷。全本地、$0：
- storage: Chroma PersistentClient（on-disk）
- embeddings: Ollama nomic-embed-text（on-box，比照 conversation_memory）

合規界線（重要）：
  * 學的是「評估經驗與方法論」——哪類目標、用了哪些評估工具、發現了哪些
    類型（severity 分佈、ATT&CK 技術分類）。這是效能與方法論資料。
  * 不學、不存攻擊技巧、exploit、payload。C 的 LLM 摘要有「攻擊導向」把關，
    偵測到規劃攻擊/利用的字眼就丟棄 LLM 文字、退回結構化摘要。
  * 只處理授權掃描的既有結果。
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

# C 的 LLM 經驗摘要「攻擊導向」把關：出現這些字眼視為越界（規劃/執行攻擊），
# 丟棄 LLM 文字、退回純結構化摘要。守住「學方法論，不學攻擊心得」。
_ATTACK_ORIENTED_TERMS = (
    "exploit", "payload", "reverse shell", "privilege escalation",
    "lateral movement", "c2", "command and control", "backdoor",
    "weaponize", "attack plan", "how to attack", "gain access",
    "pop a shell", "post-exploitation", "pivot",
)


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
        logger.warning("assess_embed_failed", error=str(exc))
        return None


def _llm_experience_summary(structured: str) -> Optional[str]:
    """用本地 LLM 把結構化評估事實寫成一段「方法論經驗」摘要。
    有「攻擊導向」把關：命中越界字眼就回 None（呼叫端退回結構化摘要）。"""
    prompt = (
        "You are a defensive security assessment assistant. Summarize the "
        "following AUTHORIZED assessment facts as a short methodology lesson: "
        "which tools surfaced which kinds of findings on this target type, and "
        "what to prioritize assessing next time. Describe findings and "
        "assessment methodology ONLY. Do NOT describe how to exploit, attack, "
        "or gain access. 2-3 sentences.\n\nFacts:\n" + structured
    )
    try:
        payload = json.dumps({
            "model": "llama3.2:3b", "prompt": prompt, "stream": False,
            "options": {"num_predict": 256, "temperature": 0.3},
        }).encode()
        req = urllib.request.Request(
            f"{_OLLAMA_BASE}/api/generate", data=payload,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            text = json.loads(r.read()).get("response", "").strip()
    except Exception as exc:  # noqa: BLE001
        logger.warning("assess_llm_summary_failed", error=str(exc))
        return None
    if not text:
        return None
    low = text.lower()
    if any(term in low for term in _ATTACK_ORIENTED_TERMS):
        logger.warning("assess_summary_rejected_attack_oriented")
        return None
    return text


def _build_structured_experience(target_type: str, tools_used: list[str],
                                 findings: list[dict]) -> str:
    """A 發現模式：把評估結果整理成結構化、客觀的經驗事實（純方法論/效能）。
    findings 每筆: {severity, attack_technique_id, attack_technique_name}。"""
    sev_dist: dict[str, int] = {}
    tech_set: list[str] = []
    for f in findings:
        s = (f.get("severity") or "info").lower()
        sev_dist[s] = sev_dist.get(s, 0) + 1
        tid = f.get("attack_technique_id")
        if tid and tid not in tech_set:
            tech_set.append(tid)
    sev_str = ", ".join(f"{k}:{v}" for k, v in sev_dist.items()) or "none"
    tools_str = ", ".join(tools_used) or "none"
    tech_str = ", ".join(tech_set) or "none"
    return (
        f"Target type: {target_type}\n"
        f"Assessment tools used: {tools_str}\n"
        f"Findings count: {len(findings)}\n"
        f"Severity distribution: {sev_str}\n"
        f"ATT&CK techniques observed (classification labels): {tech_str}"
    )


class AssessmentMemory:
    """評估經驗的存與回想（獨立 collection，與對話記憶/知識庫分開）。"""

    def __init__(self, persist_dir: str = "data/eliana_memory",
                 collection: str = "eliana_assessment_memory") -> None:
        self._persist_dir = persist_dir
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
            logger.warning("assess_mem_init_failed", error=str(exc))
            self._collection = None
        return self._collection

    def record_assessment(self, target: str, target_type: str,
                          tools_used: list[str], findings: list[dict],
                          use_llm_summary: bool = True) -> Optional[str]:
        """存一筆評估經驗（A 結構化 + 可選 C LLM 摘要）。回傳 doc_id 或 None。"""
        col = self._ensure()
        if col is None:
            return None
        structured = _build_structured_experience(
            target_type, tools_used, findings)
        # C：LLM 經驗摘要（含攻擊導向把關）；失敗/越界則只用結構化事實
        summary = _llm_experience_summary(structured) if use_llm_summary else None
        doc = structured if summary is None else f"{structured}\n\nLesson: {summary}"
        emb = _embed(doc)
        if emb is None:
            return None
        try:
            doc_id = f"assess-{int(time.time()*1000)}"
            col.add(
                ids=[doc_id], embeddings=[emb], documents=[doc],
                metadatas=[{
                    "target_type": target_type,
                    "tools": ",".join(tools_used),
                    "findings_count": len(findings),
                    "ts": time.time(),
                    "has_llm_summary": summary is not None,
                }])
            logger.info("assessment_experience_recorded",
                        target_type=target_type, findings=len(findings))
            return doc_id
        except Exception as exc:  # noqa: BLE001
            logger.warning("assess_mem_add_failed", error=str(exc))
            return None

    def recall_similar(self, query: str, k: int = 3) -> list[str]:
        """回想：回傳與 query 最相似的過往評估經驗（閉環用）。"""
        col = self._ensure()
        if col is None:
            return []
        emb = _embed(query)
        if emb is None:
            return []
        try:
            res = col.query(query_embeddings=[emb], n_results=k)
            return (res.get("documents") or [[]])[0]
        except Exception as exc:  # noqa: BLE001
            logger.warning("assess_mem_recall_failed", error=str(exc))
            return []

    def count(self) -> int:
        col = self._ensure()
        if col is None:
            return 0
        try:
            return col.count()
        except Exception:
            return 0

    def growth_series(self, days: int = 14) -> list[dict]:
        """成長趨勢（面板用）：回傳最近 `days` 天、每日「累積評估經驗筆數」。
        純計數時間序列（方法論累積量），不含任何發現內容/攻擊資料。
        誠實：沒有任何經驗就回空 list（面板顯示尚未累積）。
        回傳 [{"date": "YYYY-MM-DD", "cumulative": n}, ...]（由舊到新）。"""
        import datetime as _dt
        col = self._ensure()
        if col is None:
            return []
        try:
            # 只取 metadata 的 ts；不需 documents/embeddings（避免拉內容）
            got = col.get(include=["metadatas"])
            metas = got.get("metadatas") or []
        except Exception as exc:  # noqa: BLE001
            logger.warning("assess_growth_series_failed", error=str(exc))
            return []
        ts_list = sorted(
            float(m.get("ts", 0)) for m in metas if m and m.get("ts"))
        if not ts_list:
            return []
        today = _dt.date.today()
        start = today - _dt.timedelta(days=max(1, days) - 1)
        # 每天的累積量 = ts <= 當天 23:59:59 的經驗數
        series: list[dict] = []
        for i in range(max(1, days)):
            d = start + _dt.timedelta(days=i)
            end_of_day = _dt.datetime.combine(
                d, _dt.time.max).timestamp()
            cum = sum(1 for t in ts_list if t <= end_of_day)
            series.append({"date": d.isoformat(), "cumulative": cum})
        return series

    def recommend_priority_tools(self, target_type: str,
                                 query: str = "", k: int = 5) -> list[str]:
        """成長閉環-2（資料來源）：從過往相似評估經驗，推導「對這類目標較有
        產出的評估工具」名稱清單（依出現頻率排序）。純效能/方法論統計，供
        工具編排在階段內調序用；不涉及任何攻擊/利用決策。"""
        docs_meta = self._recall_with_meta(
            query or f"assessment of {target_type} target", k)
        tool_score: dict[str, float] = {}
        for doc, meta, score in docs_meta:
            tools = str(meta.get("tools", "")).split(",") if meta else []
            fcount = int(meta.get("findings_count", 0)) if meta else 0
            # 權重：相似度 * (1 + 發現數) — 過去在相似目標上產出多的工具優先
            w = max(0.0, float(score)) * (1.0 + fcount)
            for t in tools:
                t = t.strip()
                if t:
                    tool_score[t] = tool_score.get(t, 0.0) + w
        return [t for t, _ in sorted(tool_score.items(),
                                     key=lambda kv: kv[1], reverse=True)]

    def recall_focus_hints(self, target_type: str, query: str = "",
                           k: int = 3) -> list[str]:
        """成長閉環-3：回想過往在相似目標觀察到的「發現類型」當評估提醒。
        僅回傳發現類型/ATT&CK 分類等觀察提示（來自結構化經驗），不涉及工具
        武器化或利用步驟——守住「提示評估重點，非規劃攻擊」。"""
        docs = self.recall_similar(query or f"assessment of {target_type}", k)
        hints: list[str] = []
        for doc in docs:
            for line in doc.splitlines():
                ls = line.strip()
                # 只取「發現類型/ATT&CK 觀察」行，不取工具參數等
                if ls.startswith("ATT&CK techniques observed") or \
                   ls.startswith("Severity distribution"):
                    hints.append(ls)
        return hints

    def _recall_with_meta(self, query: str, k: int):
        col = self._ensure()
        if col is None:
            return []
        emb = _embed(query)
        if emb is None:
            return []
        try:
            res = col.query(query_embeddings=[emb], n_results=k,
                            include=["documents", "metadatas", "distances"])
            docs = (res.get("documents") or [[]])[0]
            metas = (res.get("metadatas") or [[]])[0]
            dists = (res.get("distances") or [[]])[0]
            out = []
            for i, d in enumerate(docs):
                meta = metas[i] if i < len(metas) else {}
                score = 1.0 - float(dists[i]) if i < len(dists) else 0.0
                out.append((d, meta, score))
            return out
        except Exception as exc:  # noqa: BLE001
            logger.warning("assess_recall_meta_failed", error=str(exc))
            return []
