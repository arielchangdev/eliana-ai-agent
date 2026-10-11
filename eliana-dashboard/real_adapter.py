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

本階段範圍
----------
只接「真實 ResourceMonitor」。Task_Scheduler / learning-engine 的真實 provider
不在本階段，task / knowledge / agent_state 暫時沿用 Mock，面板資源區顯示真實
雙機數據，其餘區塊顯示 Mock 佔位。
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone

# 核心（真實資料來源）
from eliana_core.services.resource_monitor import ResourceMonitor
from eliana_core.services.ssh_channel import SSHChannel
from eliana_core.models.task import HostTarget

# Dashboard 端型別與既有 Mock（非資源部分沿用）
from app.dashboard.models import SystemMetrics as DashMetrics
from app.dashboard.main import build_components
from app.dashboard.services.adapters import (
    MockTaskScheduler,
    MockKnowledgeStats,
)

logger = logging.getLogger("eliana.dashboard.real")

# HostTarget -> 面板顯示用的友善主機名
_HOST_LABEL = {
    HostTarget.CORE: os.environ.get("ELIANA_DASH__CORE_LABEL", "rhel-core"),
    HostTarget.WEAPON: os.environ.get("ELIANA_DASH__WEAPON_LABEL", "kali"),
}

POLL_INTERVAL = float(os.environ.get("ELIANA_DASH__POLL_SECONDS", "10"))


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


async def build_real_components(db_path: str = "data/dashboard.db"):
    """建立接真實 ResourceMonitor 的 dashboard components，附帶輪詢器。

    回傳 (components, poller)；呼叫端負責在 app 生命週期啟停 poller。
    """
    ssh = _build_ssh()
    monitor = ResourceMonitor(ssh_channel=ssh)

    mock_task = MockTaskScheduler()
    mock_know = MockKnowledgeStats()

    components = await build_components(
        db_path=db_path,
        resource_provider=None,  # 走 push，不需 callable
        task_provider=mock_task.get_recent_tasks,
        knowledge_provider=mock_know.get_stats,
        agent_state_provider=mock_task.get_agent_status,
    )
    poller = ResourcePoller(components.aggregator, monitor)
    return components, poller
