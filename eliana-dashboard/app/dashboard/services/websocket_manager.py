"""WebSocket Manager：管理連線池與訊息廣播。

以 client_id 追蹤每個連線，支援廣播與對單一客戶端發送快照。
斷線的客戶端會在廣播失敗時自動移除。
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from ..models import DashboardMessage


class WebSocketManager:
    def __init__(self, snapshot_provider=None):
        # client_id -> websocket
        self._connections: dict[str, Any] = {}
        self._lock = asyncio.Lock()
        # 可注入的快照產生器（回傳 DashboardSnapshot）
        self._snapshot_provider = snapshot_provider

    async def connect(self, websocket: Any) -> str:
        """接受新連線，回傳 client_id。"""
        await websocket.accept()
        client_id = str(uuid4())
        async with self._lock:
            self._connections[client_id] = websocket
        return client_id

    async def disconnect(self, client_id: str) -> None:
        """移除斷線客戶端。"""
        async with self._lock:
            self._connections.pop(client_id, None)

    async def broadcast(self, message: DashboardMessage) -> None:
        """廣播訊息至所有已連線客戶端；發送失敗者自動移除。"""
        payload = _serialize(message)
        async with self._lock:
            targets = list(self._connections.items())
        dead: list[str] = []
        for client_id, ws in targets:
            try:
                await ws.send_text(payload)
            except Exception:  # noqa: BLE001 - 發送失敗視為斷線
                dead.append(client_id)
        if dead:
            async with self._lock:
                for client_id in dead:
                    self._connections.pop(client_id, None)

    async def send_snapshot(self, client_id: str) -> None:
        """對新連線客戶端發送完整狀態快照。"""
        if self._snapshot_provider is None:
            return
        async with self._lock:
            ws = self._connections.get(client_id)
        if ws is None:
            return
        snapshot = await _maybe_await(self._snapshot_provider())
        message = DashboardMessage(type="snapshot", payload=_to_dict(snapshot))
        try:
            await ws.send_text(_serialize(message))
        except Exception:  # noqa: BLE001
            await self.disconnect(client_id)

    def get_connected_count(self) -> int:
        return len(self._connections)


# --------------------------------------------------------------------------- #
# 序列化工具
# --------------------------------------------------------------------------- #
def _serialize(message: DashboardMessage) -> str:
    return json.dumps(_to_dict(message), default=_json_default, ensure_ascii=False)


def _to_dict(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_dict(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_dict(v) for v in obj]
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


def _json_default(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


async def _maybe_await(value: Any) -> Any:
    if asyncio.iscoroutine(value):
        return await value
    return value
