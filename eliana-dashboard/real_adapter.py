"""真實資料來源 adapter：把 eliana_core 的 ResourceMonitor 接進 Dashboard。

接線重點
--------
* 核心 ResourceMonitor.collect_metrics(host: HostTarget) 一次只回單一主機、
  且用的是 eliana_core 版 SystemMetrics；Dashboard 期望的是 app.dashboard.models
  版 SystemMetrics（欄位相同、類別不同）。本模組負責「迴圈兩台 + 轉型」。
* DataAggregator 的 resources 走 push 模型（update_metrics），不會主動拉
  provider，因此需要一個背景輪詢迴圈定期推入最新指標。
* 輪詢間隔預設 10 秒：WEAPON（kali）每輪要走一次 SSH + 遠端 psutil，間隔太密
  會給 kali 不必要負載，10 秒已足夠面板即時感。

資料源現況（階段 4 延伸・第一段）
----------------------------------
* resource  : 真實 ResourceMonitor（CORE 本地 + WEAPON SSH）
* knowledge : 真實 ChromaDB 知識庫 collection 計數（誠實：沒有就顯示 0）
* agent     : 從掃描活動推導（scans.status='running' -> running，否則 idle）
* task      : 仍為 Mock，待第二段（修 ScanEngine 接 db + 讀 scans）再接真實
"""
from __future__ import annotations

import asyncio
import logging
import os
import sqlite3
from datetime import datetime, timezone

# 核心（真實資料來源）
from eliana_core.services.resource_monitor import ResourceMonitor
from eliana_core.services.ssh_channel import SSHChannel
from eliana_core.models.task import HostTarget

# Dashboard 端型別與既有 Mock（尚未接真實的部分沿用）
from app.dashboard.models import (
    SystemMetrics as DashMetrics,
    KnowledgeStats,
    AgentStatus,
    AgentState,
)
from app.dashboard.main import build_components
from app.dashboard.services.adapters import MockTaskScheduler

logger = logging.getLogger("eliana.dashboard.real")

# HostTarget -> 面板顯示用的友善主機名
_HOST_LABEL = {
    HostTarget.CORE: os.environ.get("ELIANA_DASH__CORE_LABEL", "rhel-core"),
    HostTarget.WEAPON: os.environ.get("ELIANA_DASH__WEAPON_LABEL", "kali"),
}

POLL_INTERVAL = float(os.environ.get("ELIANA_DASH__POLL_SECONDS", "10"))

# 知識庫（ChromaDB）：持久化目錄與要計數的 collection（逗號分隔）
KNOWLEDGE_CHROMA_DIR = os.environ.get(
    "ELIANA_DASH__KNOWLEDGE_DIR", "YOUR_CHROMA_DIR")
KNOWLEDGE_COLLECTIONS = [
    c.strip() for c in os.environ.get(
        "ELIANA_DASH__KNOWLEDGE_COLLECTIONS",
        "eliana_knowledge,ariel_knowledge").split(",") if c.strip()
]

# bounty 掃描資料庫（agent 狀態推導 + 第二段 task provider）
BOUNTY_DB = os.environ.get("ELIANA_BOUNTY__DB", "YOUR_BOUNTY_DB")

# 對話記憶（ChromaDB）與人格資料庫（成長狀態）
MEMORY_CHROMA_DIR = os.environ.get("ELIANA_DASH__MEMORY_DIR", "YOUR_MEMORY_DIR")
MEMORY_COLLECTION = os.environ.get(
    "ELIANA_DASH__MEMORY_COLLECTION", "eliana_conversations")
PERSONALITY_DB = os.environ.get(
    "ELIANA_DASH__PERSONALITY_DB", "YOUR_PERSONALITY_DB")

# 知識庫 collection -> 人話標籤（不在面板露出技術 collection 名）
_KNOWLEDGE_LABELS = {
    "eliana_knowledge": "對話中學到",
    "ariel_knowledge": "你教的",
}


# --------------------------------------------------------------------------- #
# resource（真實 ResourceMonitor）
# --------------------------------------------------------------------------- #
def _aware_utc(dt) -> datetime:
    """正規化為 aware UTC。核心的本地指標 timestamp 可能是 naive，
    直接丟給 aggregator 會在 (now - ts) 觸發 naive/aware 相減 TypeError。"""
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _to_dash_metrics(core_m, label: str) -> DashMetrics:
    """eliana_core SystemMetrics -> dashboard SystemMetrics（欄位對拷）。"""
    return DashMetrics(
        host=label,
        cpu_percent=core_m.cpu_percent,
        memory_percent=core_m.memory_percent,
        memory_used_gb=core_m.memory_used_gb,
        memory_total_gb=core_m.memory_total_gb,
        disk_percent=core_m.disk_percent,
        disk_used_gb=core_m.disk_used_gb,
        disk_total_gb=core_m.disk_total_gb,
        timestamp=_aware_utc(getattr(core_m, "timestamp", None)),
        stale=False,
    )


def _build_ssh() -> SSHChannel:
    host = os.environ.get("ELIANA_WEAPON__HOST", "YOUR_WEAPON_HOST")
    user = os.environ.get("ELIANA_WEAPON__USER", "YOUR_WEAPON_USER")
    key = os.environ.get("ELIANA_WEAPON__KEY", "/etc/eliana/keys/kali_ed25519")
    return SSHChannel(host=host, username=user,
                      private_key_path=key, known_hosts_path=None,
                      connect_timeout=8.0)


class ResourcePoller:
    """背景輪詢：定期 collect 兩台並 push 進 aggregator。"""

    def __init__(self, aggregator, monitor: ResourceMonitor,
                 interval: float = POLL_INTERVAL):
        self._agg = aggregator
        self._mon = monitor
        self._interval = interval
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    async def _ensure_ssh(self) -> None:
        """WEAPON 透過 SSH 採集；核心 _collect_remote_metrics 不會自動連線，
        因此輪詢前確保通道已建立（比照 authorized_scan 的掃描前自動 connect）。"""
        ssh = getattr(self._mon, "_ssh_channel", None)
        if ssh is None:
            return
        try:
            connected = ssh.is_connected
        except Exception:
            connected = False
        if not connected:
            await ssh.connect()

    async def _poll_once(self) -> None:
        for host in (HostTarget.CORE, HostTarget.WEAPON):
            label = _HOST_LABEL[host]
            try:
                if host == HostTarget.WEAPON:
                    await self._ensure_ssh()
                core_m = await self._mon.collect_metrics(host)
                self._agg.update_metrics(_to_dash_metrics(core_m, label))
                logger.debug("metrics pushed host=%s cpu=%.1f", label,
                             core_m.cpu_percent)
            except Exception as exc:  # 單台失敗不影響另一台/整個迴圈
                logger.warning("collect_metrics failed host=%s: %s", label, exc)

    async def _loop(self) -> None:
        logger.info("resource poller started interval=%.0fs", self._interval)
        while not self._stop.is_set():
            await self._poll_once()
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
            except asyncio.TimeoutError:
                pass
        logger.info("resource poller stopped")

    async def start(self) -> None:
        # 啟動時先同步 poll 一次，確保面板一開就有資料（WEAPON 失敗也無妨）
        await self._poll_once()
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()


# --------------------------------------------------------------------------- #
# knowledge（真實 ChromaDB 計數）
# --------------------------------------------------------------------------- #
def _count_knowledge_sync() -> tuple[int, dict]:
    """同步讀 ChromaDB 各 collection 計數。只需要數量，不實例化完整
    VectorStore（避免拉 embedder 模型）。讀不到就誠實回 0。"""
    try:
        import chromadb
        client = chromadb.PersistentClient(path=KNOWLEDGE_CHROMA_DIR)
    except Exception as exc:  # 目錄不存在 / chroma 載入失敗
        logger.warning("knowledge chroma open failed: %s", exc)
        return 0, {}

    per_collection: dict[str, int] = {}
    total = 0
    for name in KNOWLEDGE_COLLECTIONS:
        try:
            col = client.get_collection(name)
            n = col.count()
            per_collection[name] = n
            total += n
        except Exception:
            # collection 不存在就跳過（誠實：不存在不計入）
            per_collection[name] = 0
    return total, per_collection


def _count_memory_sync() -> int:
    """對話記憶（長期記憶）段數。讀不到就 0。"""
    try:
        import chromadb
        client = chromadb.PersistentClient(path=MEMORY_CHROMA_DIR)
        return int(client.get_collection(MEMORY_COLLECTION).count())
    except Exception as exc:
        logger.warning("memory count failed: %s", exc)
        return 0


def _personality_growth_sync() -> dict:
    """讀 personality.db：目前版本、是否演化過、關鍵參數（人話）。

    誠實：evolution_log 為空 -> 顯示尚未演化；只讀最新版本快照的參數。
    """
    out = {
        "版本": 0,
        "已演化次數": 0,
        "主動性": None,
        "幽默感": None,
        "表情頻率": None,
    }
    try:
        conn = sqlite3.connect(PERSONALITY_DB)
        try:
            # 目前版本號 = personality_versions 最大 version_number
            row = conn.execute(
                "SELECT version_number, profile_snapshot FROM personality_versions"
                " ORDER BY version_number DESC LIMIT 1"
            ).fetchone()
            if row:
                out["版本"] = int(row[0])
                try:
                    import json
                    snap = json.loads(row[1])
                    rs = snap.get("response_strategy", {})
                    comm = snap.get("communication", {})
                    out["主動性"] = rs.get("proactiveness")
                    out["幽默感"] = rs.get("humor_ratio")
                    out["表情頻率"] = comm.get("emoji_frequency")
                except Exception:
                    pass
            # 實際發生的演化次數 = evolution_log 中 status 已套用的筆數
            n = conn.execute(
                "SELECT COUNT(*) FROM evolution_log WHERE status = 'applied'"
            ).fetchone()
            out["已演化次數"] = int(n[0]) if n else 0
        finally:
            conn.close()
    except Exception as exc:
        logger.warning("personality growth read failed: %s", exc)
    return out


async def real_knowledge_provider() -> KnowledgeStats:
    """回傳「Eliana 成長狀態」。全部真實，沒資料就 0 / 尚未開始，不塞假數字。

    承載方式（不改既有 schema）：
      * total_fragments        : 知識總筆數
      * category_distribution  : 人話知識分類 {"對話中學到":6, "你教的":4}
      * strategy_summary       : 成長摘要（長期記憶段數、人格版本/演化/參數）
    前端 KnowledgeStats.vue 以「成長狀態」人話呈現這些鍵。
    """
    total, per_collection = await asyncio.to_thread(_count_knowledge_sync)
    memory_segments = await asyncio.to_thread(_count_memory_sync)
    growth = await asyncio.to_thread(_personality_growth_sync)

    # collection 技術名 -> 人話標籤
    friendly = {}
    for name, n in per_collection.items():
        friendly[_KNOWLEDGE_LABELS.get(name, name)] = n

    strategy_summary = {
        "長期記憶段數": memory_segments,
        "人格版本": growth["版本"],
        "已演化次數": growth["已演化次數"],
        "主動性": growth["主動性"],
        "幽默感": growth["幽默感"],
        "表情頻率": growth["表情頻率"],
    }

    return KnowledgeStats(
        total_fragments=total,
        category_distribution=friendly,
        daily_growth=[],
        last_crawl_time=None,
        last_crawl_status=None,
        next_crawl_time=None,
        strategy_summary=strategy_summary,
    )


# --------------------------------------------------------------------------- #
# agent state（從掃描活動推導）
# --------------------------------------------------------------------------- #
def _running_scans_sync() -> int:
    """查 bounty.db 是否有 status='running' 的掃描。讀不到就當 0（idle）。"""
    try:
        conn = sqlite3.connect(BOUNTY_DB)
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE status = 'running'"
            ).fetchone()
            return int(row[0]) if row else 0
        finally:
            conn.close()
    except Exception as exc:
        logger.warning("agent-state scans query failed: %s", exc)
        return 0


async def real_agent_state_provider() -> AgentStatus:
    """從掃描活動推導 agent 狀態：有掃描在跑 -> running，否則 idle。

    目前沒有單一權威狀態來源；以「bounty.db 是否有 running 掃描」作為
    最務實的真實信號。沒有掃描在跑時誠實顯示 idle。
    """
    running = await asyncio.to_thread(_running_scans_sync)
    if running > 0:
        return AgentStatus(
            state=AgentState.RUNNING,
            current_task_name=f"{running} scan(s) running",
            current_task_progress=0.0,
        )
    return AgentStatus(
        state=AgentState.IDLE,
        current_task_name=None,
        current_task_progress=0.0,
    )


# --------------------------------------------------------------------------- #
# 組裝
# --------------------------------------------------------------------------- #
async def build_real_components(db_path: str = "data/dashboard.db"):
    """建立接真實資料源的 dashboard components，附帶資源輪詢器。

    第一段：resource / knowledge / agent_state 為真實；task 仍 Mock。
    回傳 (components, poller)；呼叫端負責在 app 生命週期啟停 poller。
    """
    ssh = _build_ssh()
    monitor = ResourceMonitor(ssh_channel=ssh)

    mock_task = MockTaskScheduler()

    components = await build_components(
        db_path=db_path,
        resource_provider=None,  # 走 push，不需 callable
        task_provider=mock_task.get_recent_tasks,       # 第二段才接真實
        knowledge_provider=real_knowledge_provider,     # 真實
        agent_state_provider=real_agent_state_provider,  # 真實
    )
    poller = ResourcePoller(components.aggregator, monitor)
    return components, poller
