"""WebSocket API 端點。"""
from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect


def create_websocket_router(ws_manager) -> APIRouter:
    router = APIRouter()

    @router.websocket("/ws/dashboard")
    async def dashboard_websocket(websocket: WebSocket) -> None:
        """Dashboard 即時更新 WebSocket 端點。

        連線時立即發送完整快照，之後持續接收廣播直到斷線。
        """
        client_id = await ws_manager.connect(websocket)
        try:
            await ws_manager.send_snapshot(client_id)
            while True:
                # 保持連線；前端通常不主動傳訊，但需接收以偵測斷線
                await websocket.receive_text()
        except WebSocketDisconnect:
            await ws_manager.disconnect(client_id)
        except Exception:  # noqa: BLE001
            await ws_manager.disconnect(client_id)

    return router
