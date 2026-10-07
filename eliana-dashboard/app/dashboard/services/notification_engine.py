"""Notification Engine：通知排程、優先級分類與批次彙整。

- classify_priority / should_send_immediately / format_notification 為純函式
- URGENT 立即發送；NORMAL 每 5 分鐘批次；LOW 每 30 分鐘批次
- 支援通知偏好（停用類別、靜音時段，urgent 可覆蓋靜音）
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Callable, Optional

from ..models import (
    Notification,
    NotificationPreferences,
    NotificationPriority,
)

# 批次 flush 間隔（秒）
NORMAL_INTERVAL = 300   # 5 分鐘
LOW_INTERVAL = 1800     # 30 分鐘

# 連續失敗達此次數視為緊急
CONSECUTIVE_FAILURE_THRESHOLD = 3

# 事件類型分類
_URGENT_EVENTS = {"resource_alert", "authorization_request"}
_NORMAL_EVENTS = {"task_completion", "status_change"}


class NotificationEngine:
    def __init__(
        self,
        sender: Callable,  # async callable(text) -> bool
        preferences: Optional[NotificationPreferences] = None,
    ):
        self._sender = sender
        self.preferences = preferences or NotificationPreferences()
        self._queues: dict[NotificationPriority, list[Notification]] = {
            NotificationPriority.NORMAL: [],
            NotificationPriority.LOW: [],
        }
        self._scheduler_tasks: list[asyncio.Task] = []
        self._running = False

    # ----- 佇列與發送 ----------------------------------------------------- #
    async def enqueue_notification(self, notification: Notification) -> None:
        """加入佇列；URGENT 立即發送，其餘依優先級批次。"""
        if not self._is_allowed(notification):
            return
        if should_send_immediately(notification):
            await self._send(notification)
        else:
            self._queues.setdefault(notification.priority, []).append(notification)

    async def flush_batch(self, priority: NotificationPriority) -> int:
        """發送指定優先級的批次通知，回傳發送數量。"""
        queue = self._queues.get(priority, [])
        if not queue:
            return 0
        # 批次彙整為單一訊息
        lines = [format_notification(n) for n in queue]
        count = len(queue)
        self._queues[priority] = []
        await self._sender("\n\n".join(lines))
        return count

    async def _send(self, notification: Notification) -> None:
        await self._sender(format_notification(notification))
        notification.sent_at = datetime.now(timezone.utc)

    # ----- 偏好判斷 ------------------------------------------------------- #
    def _is_allowed(self, notification: Notification) -> bool:
        """依偏好判斷是否應發送（類別啟用 + 靜音時段）。"""
        prefs = self.preferences
        # 類別過濾
        if "all" not in prefs.enabled_categories:
            if notification.event_type not in prefs.enabled_categories:
                return False
        # 靜音時段
        if self._in_mute_window():
            if notification.priority == NotificationPriority.URGENT and prefs.urgent_override_mute:
                return True
            return False
        return True

    def _in_mute_window(self, now: Optional[datetime] = None) -> bool:
        prefs = self.preferences
        if prefs.mute_start_hour is None or prefs.mute_end_hour is None:
            return False
        hour = (now or datetime.now(timezone.utc)).hour
        start, end = prefs.mute_start_hour, prefs.mute_end_hour
        if start <= end:
            return start <= hour < end
        # 跨午夜（如 22:00-06:00）
        return hour >= start or hour < end

    def update_preferences(self, preferences: NotificationPreferences) -> None:
        self.preferences = preferences

    # ----- 排程 ----------------------------------------------------------- #
    async def start_scheduler(self) -> None:
        """啟動定期 flush 排程。"""
        self._running = True
        self._scheduler_tasks = [
            asyncio.create_task(self._flush_loop(NotificationPriority.NORMAL, NORMAL_INTERVAL)),
            asyncio.create_task(self._flush_loop(NotificationPriority.LOW, LOW_INTERVAL)),
        ]

    async def stop_scheduler(self) -> None:
        self._running = False
        for task in self._scheduler_tasks:
            task.cancel()
        for task in self._scheduler_tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._scheduler_tasks = []

    async def _flush_loop(self, priority: NotificationPriority, interval: int) -> None:
        while self._running:
            await asyncio.sleep(interval)
            try:
                await self.flush_batch(priority)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                pass


# --------------------------------------------------------------------------- #
# 純函式（供 property test 直接驗證）
# --------------------------------------------------------------------------- #
def classify_priority(event_type: str, context: dict) -> NotificationPriority:
    """根據事件類型與上下文分類通知優先級。

    - 資源告警、授權請求、連續失敗 >= 3 → URGENT
    - 單次任務完成、狀態變更 → NORMAL
    - 其餘（資訊）→ LOW
    """
    if event_type in _URGENT_EVENTS:
        return NotificationPriority.URGENT
    if event_type == "task_failure":
        consecutive = context.get("consecutive_failures", 0)
        if consecutive >= CONSECUTIVE_FAILURE_THRESHOLD:
            return NotificationPriority.URGENT
        return NotificationPriority.NORMAL
    if event_type in _NORMAL_EVENTS:
        return NotificationPriority.NORMAL
    return NotificationPriority.LOW


def should_send_immediately(notification: Notification) -> bool:
    """僅 URGENT 立即發送。"""
    return notification.priority == NotificationPriority.URGENT


def format_notification(notification: Notification) -> str:
    """格式化通知訊息，含事件標記、時間戳、摘要（有連結則附上）。"""
    tag = f"[{notification.event_type or 'event'}]"
    ts = notification.created_at.isoformat()
    parts = [f"{tag} {notification.title}".strip(), f"時間: {ts}", notification.summary]
    if notification.link:
        parts.append(f"連結: {notification.link}")
    return "\n".join(p for p in parts if p)
