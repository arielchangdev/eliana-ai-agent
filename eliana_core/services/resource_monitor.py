"""資源監控服務，採集系統指標。"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Optional

import psutil

from eliana_core.db import metrics_repo
from eliana_core.db.database import DatabasePool
from eliana_core.models.metrics import Alert, AlertLevel, DirUsage, SystemMetrics
from eliana_core.models.constants import ALERT_THRESHOLDS
from eliana_core.models.task import HostTarget

if TYPE_CHECKING:
    from eliana_core.services.ssh_channel import SSHChannel

logger = logging.getLogger(__name__)


class ResourceMonitor:
    """資源監控服務，採集指標並觸發告警。"""

    def __init__(
        self,
        ssh_channel: Optional["SSHChannel"] = None,
        db_pool: Optional[DatabasePool] = None,
    ) -> None:
        """初始化 ResourceMonitor。

        Args:
            ssh_channel: 可選的 SSH 通道，用於遠端主機指標採集。
                         若未提供，僅支援本地指標採集。
            db_pool: 可選的資料庫連線池，用於儲存與查詢監控數據。
                     若未提供，store_metrics/query_history/cleanup_old_data 將無法使用。
        """
        self._ssh_channel = ssh_channel
        self._db_pool = db_pool
        self._monitoring_task: Optional[asyncio.Task[None]] = None
        self._stop_event = asyncio.Event()

    # --- 資料儲存與查詢（委派至 MetricsRepository）---

    async def store_metrics(self, metrics: SystemMetrics) -> None:
        """儲存指標數據（保留 7 天）。

        委派至 MetricsRepository.store_metrics() 將指標寫入 SQLite。

        Args:
            metrics: 系統指標資料。

        Raises:
            RuntimeError: 若資料庫連線池未設定。
        """
        if self._db_pool is None:
            raise RuntimeError(
                "Database pool not configured; cannot store metrics"
            )
        await metrics_repo.store_metrics(self._db_pool, metrics)

    async def query_history(
        self, host: HostTarget, start: datetime, end: datetime
    ) -> list[SystemMetrics]:
        """查詢歷史監控數據。

        委派至 MetricsRepository.query_history()。

        Args:
            host: 目標主機。
            start: 查詢起始時間。
            end: 查詢結束時間。

        Returns:
            SystemMetrics 列表，依時間排序。

        Raises:
            RuntimeError: 若資料庫連線池未設定。
        """
        if self._db_pool is None:
            raise RuntimeError(
                "Database pool not configured; cannot query history"
            )
        return await metrics_repo.query_history(self._db_pool, host, start, end)

    async def cleanup_old_data(self, retention_days: int = 7) -> int:
        """清理過期數據，回傳刪除筆數。

        委派至 MetricsRepository.cleanup_old_data()。

        Args:
            retention_days: 資料保留天數，預設 7 天。

        Returns:
            刪除的記錄筆數。

        Raises:
            RuntimeError: 若資料庫連線池未設定。
        """
        if self._db_pool is None:
            raise RuntimeError(
                "Database pool not configured; cannot cleanup old data"
            )
        return await metrics_repo.cleanup_old_data(self._db_pool, retention_days)

    # --- 背景監控循環 ---

    async def start_monitoring_loop(self) -> None:
        """啟動背景監控循環，每 10 秒自動採集並儲存指標。

        監控循環會採集本地主機 (CORE) 的指標，若 SSH 通道可用也會
        嘗試採集遠端主機 (WEAPON) 的指標。採集到的指標會自動儲存
        至資料庫，並在每次循環中清理過期數據。

        若循環已在執行，此方法不會重複啟動。
        """
        if self._monitoring_task is not None and not self._monitoring_task.done():
            logger.warning("監控循環已在執行中，跳過重複啟動")
            return

        self._stop_event.clear()
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("背景監控循環已啟動（採集間隔：10 秒）")

    async def stop_monitoring_loop(self) -> None:
        """停止背景監控循環。

        優雅地停止循環並等待當前採集完成。
        """
        if self._monitoring_task is None or self._monitoring_task.done():
            return

        self._stop_event.set()
        try:
            await asyncio.wait_for(self._monitoring_task, timeout=15.0)
        except asyncio.TimeoutError:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
        self._monitoring_task = None
        logger.info("背景監控循環已停止")

    async def _monitoring_loop(self) -> None:
        """內部監控循環實作：每 10 秒採集、儲存並評估指標。"""
        while not self._stop_event.is_set():
            try:
                # 採集本地主機指標
                core_metrics = await self.collect_metrics(HostTarget.CORE)
                await self.store_metrics(core_metrics)
                logger.debug("已儲存 Core_Host 指標: cpu=%.1f%%", core_metrics.cpu_percent)

                # 嘗試採集遠端主機指標（若 SSH 可用）
                if self._ssh_channel is not None:
                    try:
                        weapon_metrics = await self.collect_metrics(HostTarget.WEAPON)
                        await self.store_metrics(weapon_metrics)
                        logger.debug(
                            "已儲存 Weapon_Host 指標: cpu=%.1f%%",
                            weapon_metrics.cpu_percent,
                        )
                    except Exception as e:
                        logger.warning("遠端指標採集失敗: %s", e)

                # 定期清理過期數據（每次循環都清理，操作是冪等的）
                deleted = await self.cleanup_old_data()
                if deleted > 0:
                    logger.info("已清理 %d 筆過期監控數據", deleted)

            except RuntimeError as e:
                # 資料庫未設定等情況，記錄警告但不中斷循環
                logger.warning("監控循環儲存失敗: %s", e)
            except Exception as e:
                logger.error("監控循環異常: %s", e, exc_info=True)

            # 等待 10 秒或直到收到停止信號
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=10.0)
                # 若 wait 正常完成，代表收到 stop 信號
                break
            except asyncio.TimeoutError:
                # 超時代表 10 秒已過，繼續下一輪
                continue

    # --- 指標採集 ---

    async def collect_metrics(self, host: HostTarget) -> SystemMetrics:
        """採集指定主機的系統指標。

        對本地主機 (CORE) 使用 psutil 直接採集；
        對遠端主機 (WEAPON) 透過 SSH 執行指標採集腳本。

        Args:
            host: 目標主機。

        Returns:
            SystemMetrics: 採集到的系統指標。

        Raises:
            RuntimeError: 遠端採集時 SSH 通道未設定或指令執行失敗。
        """
        if host == HostTarget.CORE:
            return self._collect_local_metrics(host)
        else:
            return await self._collect_remote_metrics(host)

    def _collect_local_metrics(self, host: HostTarget) -> SystemMetrics:
        """使用 psutil 採集本地系統指標。"""
        cpu_percent = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        return SystemMetrics(
            host=host,
            cpu_percent=cpu_percent,
            memory_percent=memory.percent,
            memory_used_gb=memory.used / (1024**3),
            memory_total_gb=memory.total / (1024**3),
            disk_percent=disk.percent,
            disk_used_gb=disk.used / (1024**3),
            disk_total_gb=disk.total / (1024**3),
            timestamp=datetime.utcnow(),
        )

    async def _collect_remote_metrics(self, host: HostTarget) -> SystemMetrics:
        """透過 SSH 執行指標採集腳本取得遠端主機指標。"""
        if self._ssh_channel is None:
            raise RuntimeError(
                "SSH channel not configured; cannot collect remote metrics"
            )

        # 遠端採集腳本：輸出 JSON 格式的系統指標
        script = (
            "python3 -c \""
            "import psutil, json; "
            "mem = psutil.virtual_memory(); "
            "disk = psutil.disk_usage('/'); "
            "print(json.dumps({"
            "'cpu_percent': psutil.cpu_percent(interval=0.1), "
            "'memory_percent': mem.percent, "
            "'memory_used_gb': mem.used / (1024**3), "
            "'memory_total_gb': mem.total / (1024**3), "
            "'disk_percent': disk.percent, "
            "'disk_used_gb': disk.used / (1024**3), "
            "'disk_total_gb': disk.total / (1024**3)"
            "}))\""
        )

        result = await self._ssh_channel.execute_remote(script, timeout=10.0)

        if result.exit_code != 0:
            raise RuntimeError(
                f"Remote metrics collection failed: {result.stderr}"
            )

        data = json.loads(result.stdout.strip())
        return SystemMetrics(
            host=host,
            cpu_percent=data["cpu_percent"],
            memory_percent=data["memory_percent"],
            memory_used_gb=data["memory_used_gb"],
            memory_total_gb=data["memory_total_gb"],
            disk_percent=data["disk_percent"],
            disk_used_gb=data["disk_used_gb"],
            disk_total_gb=data["disk_total_gb"],
            timestamp=datetime.utcnow(),
        )

    # --- 閾值評估 ---

    def evaluate_thresholds(self, metrics: SystemMetrics) -> list[Alert]:
        """根據閾值評估指標，產生告警列表（純函式）。

        檢查 CPU、記憶體、磁碟使用率是否超過設定閾值，
        並產生對應的告警。持續時間的追蹤由監控循環層處理，
        此函式僅根據當前指標值判斷是否超標。

        Args:
            metrics: 系統指標資料。

        Returns:
            list[Alert]: 符合條件的告警列表。
        """
        alerts: list[Alert] = []

        # CPU >= 90% -> CRITICAL 告警
        cpu_config = ALERT_THRESHOLDS["cpu_critical"]
        if metrics.cpu_percent >= cpu_config["threshold"]:
            alerts.append(Alert(
                level=cpu_config["level"],
                host=metrics.host,
                metric_name="cpu_percent",
                current_value=metrics.cpu_percent,
                threshold_value=cpu_config["threshold"],
                message=(
                    f"CPU usage {metrics.cpu_percent:.1f}% exceeds "
                    f"threshold {cpu_config['threshold']:.1f}%"
                ),
                triggered_at=metrics.timestamp,
            ))

        # Memory >= 85% -> WARNING 告警
        memory_config = ALERT_THRESHOLDS["memory_warning"]
        if metrics.memory_percent >= memory_config["threshold"]:
            alerts.append(Alert(
                level=memory_config["level"],
                host=metrics.host,
                metric_name="memory_percent",
                current_value=metrics.memory_percent,
                threshold_value=memory_config["threshold"],
                message=(
                    f"Memory usage {metrics.memory_percent:.1f}% exceeds "
                    f"threshold {memory_config['threshold']:.1f}%"
                ),
                triggered_at=metrics.timestamp,
            ))

        # Disk >= 80% -> WARNING 告警
        disk_config = ALERT_THRESHOLDS["disk_warning"]
        if metrics.disk_percent >= disk_config["threshold"]:
            alerts.append(Alert(
                level=disk_config["level"],
                host=metrics.host,
                metric_name="disk_percent",
                current_value=metrics.disk_percent,
                threshold_value=disk_config["threshold"],
                message=(
                    f"Disk usage {metrics.disk_percent:.1f}% exceeds "
                    f"threshold {disk_config['threshold']:.1f}%"
                ),
                triggered_at=metrics.timestamp,
            ))

        return alerts

    # --- 目錄空間分析 ---

    async def get_top_directories(
        self, host: HostTarget, count: int = 5
    ) -> list[DirUsage]:
        """取得佔用空間最大的目錄。

        對本地主機使用 psutil/os 掃描；
        對遠端主機透過 SSH 執行 du 指令。

        Args:
            host: 目標主機。
            count: 回傳的目錄數量，預設為 5。

        Returns:
            list[DirUsage]: 依空間使用量降序排列的目錄列表。

        Raises:
            RuntimeError: 遠端查詢時 SSH 通道未設定或指令執行失敗。
        """
        if host == HostTarget.CORE:
            return self._get_local_top_directories(count)
        else:
            return await self._get_remote_top_directories(count)

    def _get_local_top_directories(self, count: int) -> list[DirUsage]:
        """使用 du 等效邏輯取得本地佔用空間最大的目錄。

        掃描根目錄下的第一層子目錄。
        """
        import os
        import platform

        # 根據平台選擇掃描起點
        if platform.system() == "Windows":
            scan_root = "C:\\"
        else:
            scan_root = "/"

        dir_sizes: list[DirUsage] = []

        try:
            entries = os.listdir(scan_root)
        except PermissionError:
            return []

        for entry in entries:
            full_path = os.path.join(scan_root, entry)
            if not os.path.isdir(full_path):
                continue
            try:
                total_size = 0
                for dirpath, _dirnames, filenames in os.walk(full_path):
                    for fname in filenames:
                        try:
                            fp = os.path.join(dirpath, fname)
                            total_size += os.path.getsize(fp)
                        except (OSError, PermissionError):
                            continue
                    # 限制遍歷深度避免效能問題：只計算前兩層
                    depth = dirpath[len(full_path):].count(os.sep)
                    if depth >= 2:
                        break
                dir_sizes.append(
                    DirUsage(path=full_path, size_gb=total_size / (1024**3))
                )
            except (OSError, PermissionError):
                continue

        # 依大小降序排列，取前 count 筆
        dir_sizes.sort(key=lambda d: d.size_gb, reverse=True)
        return dir_sizes[:count]

    async def _get_remote_top_directories(self, count: int) -> list[DirUsage]:
        """透過 SSH 執行 du 指令取得遠端佔用空間最大的目錄。"""
        if self._ssh_channel is None:
            raise RuntimeError(
                "SSH channel not configured; cannot query remote directories"
            )

        # 使用 du 取得根目錄下第一層子目錄的大小
        command = f"du -sh /* 2>/dev/null | sort -rh | head -n {count}"
        result = await self._ssh_channel.execute_remote(command, timeout=30.0)

        if result.exit_code != 0 and not result.stdout.strip():
            raise RuntimeError(
                f"Remote directory scan failed: {result.stderr}"
            )

        dir_usages: list[DirUsage] = []
        for line in result.stdout.strip().splitlines():
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            size_str, path = parts
            size_gb = self._parse_size_to_gb(size_str)
            dir_usages.append(DirUsage(path=path, size_gb=size_gb))

        return dir_usages[:count]

    @staticmethod
    def _parse_size_to_gb(size_str: str) -> float:
        """將 du 輸出的人類可讀大小字串轉為 GB。

        支援格式：1.5G、500M、100K、1024 (bytes)。
        """
        size_str = size_str.strip()
        if not size_str:
            return 0.0

        suffix = size_str[-1].upper()
        try:
            if suffix == "T":
                return float(size_str[:-1]) * 1024
            elif suffix == "G":
                return float(size_str[:-1])
            elif suffix == "M":
                return float(size_str[:-1]) / 1024
            elif suffix == "K":
                return float(size_str[:-1]) / (1024 * 1024)
            else:
                # 假設是 bytes
                return float(size_str) / (1024**3)
        except ValueError:
            return 0.0
