"""Event_Bus — 模組間非同步事件匯流排。

支援 publish/subscribe/unsubscribe，內部以 asyncio.Queue 承載事件，
分派迴圈以 create_task 並行分派至訂閱者。分派失敗的事件進入重試佇列，
5 秒後重新分派，最多重試 3 次；超過上限標記為永久失敗並記錄 warning。
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Awaitable, Callable

import structlog

from .models import Event

logger = structlog.get_logger(__name__)

Handler = Callable[[Event], Awaitable[None]]

MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 5.0


class EventBus:
    """非同步 publish/subscribe 事件匯流排。"""

    def __init__(self, *, retry_delay: float = RETRY_DELAY_SECONDS,
                 max_retries: int = MAX_RETRIES) -> None:
        self._subscribers: dict[str, list[Handler]] = defaultdict(list)
        self._queue: asyncio.Queue[Event] = asyncio.Queue()
        self._retry_queue: asyncio.Queue[Event] = asyncio.Queue()
        self._retry_delay = retry_delay
        self._max_retries = max_retries
        self._running = False
        self._tasks: list[asyncio.Task] = []
        self._inflight: set[asyncio.Task] = set()
        # 永久失敗事件（供測試/監控查詢）
        self.dead_letters: list[Event] = []

    # ------------------------------------------------------------------ #
    # 訂閱管理
    # ------------------------------------------------------------------ #
    def subscribe(self, topic: str, handler: Handler) -> None:
        """訂閱某主題。同一 handler 對同一主題僅登記一次。"""
        if handler not in self._subscribers[topic]:
            self._subscribers[topic].append(handler)

    def unsubscribe(self, topic: str, handler: Handler) -> None:
        """取消訂閱。不存在時安靜忽略。"""
        if handler in self._subscribers.get(topic, []):
            self._subscribers[topic].remove(handler)

    def subscriber_count(self, topic: str) -> int:
        return len(self._subscribers.get(topic, []))

    # ------------------------------------------------------------------ #
    # 發布
    # ------------------------------------------------------------------ #
    async def publish(self, event: Event) -> None:
        """將事件放入佇列等待分派。"""
        await self._queue.put(event)

    async def publish_and_wait(self, event: Event) -> None:
        """發布並立即同步分派（測試用，繞過背景迴圈）。"""
        await self._dispatch(event)

    # ------------------------------------------------------------------ #
    # 生命週期
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._tasks = [
            asyncio.create_task(self._dispatch_loop()),
            asyncio.create_task(self._retry_loop()),
        ]

    async def stop(self) -> None:
        self._running = False
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass
        # 等待仍在進行中的分派任務
        for t in list(self._inflight):
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        self._tasks = []

    # ------------------------------------------------------------------ #
    # 內部分派
    # ------------------------------------------------------------------ #
    async def _dispatch_loop(self) -> None:
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=0.1)
            except asyncio.TimeoutError:
                continue
            await self._dispatch(event)

    async def _retry_loop(self) -> None:
        while self._running:
            try:
                event = await asyncio.wait_for(self._retry_queue.get(), timeout=0.1)
            except asyncio.TimeoutError:
                continue
            await asyncio.sleep(self._retry_delay)
            await self._dispatch(event)

    async def _dispatch(self, event: Event) -> None:
        """分派事件至所有訂閱者，逐一處理失敗並排入重試。"""
        handlers = list(self._subscribers.get(event.topic, []))
        results = await asyncio.gather(
            *(self._invoke(h, event) for h in handlers),
            return_exceptions=True,
        )
        if any(isinstance(r, Exception) for r in results):
            self._schedule_retry(event)

    async def _invoke(self, handler: Handler, event: Event) -> None:
        await handler(event)

    def _schedule_retry(self, event: Event) -> None:
        if event.retry_count >= self._max_retries:
            logger.warning("event_permanently_failed",
                           topic=event.topic, event_id=event.event_id,
                           retry_count=event.retry_count)
            self.dead_letters.append(event)
            return
        retried = event.model_copy(update={"retry_count": event.retry_count + 1})
        self._retry_queue.put_nowait(retried)
