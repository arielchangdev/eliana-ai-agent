"""Telegram Bot Handler：指令解析、白名單驗證、授權互動、限流重試。

純函式（parse_command / validate_user / format_status_reply）不相依
python-telegram-bot，供 property test 直接驗證。實際訊息發送與 Inline
Keyboard 互動於整合階段接真實 Bot API（lazy import telegram）。
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Callable, Optional

from ..errors import TelegramRateLimitError, UnauthorizedAccessError
from ..models import (
    AgentStatus,
    AuthorizationDecision,
    AuthorizationRequest,
    CommandType,
    RemoteCommand,
)

logger = logging.getLogger(__name__)

_COMMAND_MAP = {
    "/scan": CommandType.SCAN,
    "/pause": CommandType.PAUSE,
    "/resume": CommandType.RESUME,
    "/stop": CommandType.STOP,
    "/status": CommandType.STATUS,
}


class TelegramBotHandler:
    def __init__(
        self,
        whitelist: list[int],
        command_dispatcher: Optional[Callable] = None,
        auth_gate_callback: Optional[Callable] = None,
        db=None,
        send_fn: Optional[Callable] = None,
    ):
        self.whitelist = set(whitelist)
        self._dispatcher = command_dispatcher
        self._auth_gate_callback = auth_gate_callback
        self.db = db
        # 注入式發送函式（async callable(text)->None）；未提供時為 no-op
        self._send_fn = send_fn

    # ----- 遠端指令處理 --------------------------------------------------- #
    async def handle_command(self, user_id: int, text: str) -> str:
        """驗證使用者 → 解析指令 → 轉發 → 回覆結果摘要。

        未授權使用者：記錄審計日誌並拒絕。
        """
        if not self.validate_user(user_id):
            await self._log_unauthorized(user_id, text)
            raise UnauthorizedAccessError(user_id, text)

        command = self.parse_command(text)
        if command is None:
            return "無法辨識的指令"
        command.user_id = user_id
        command.raw_text = text

        if self._dispatcher is not None:
            result = await _maybe_await(self._dispatcher(command))
            return str(result)
        return f"指令 {command.command_type.value} 已接收"

    async def _log_unauthorized(self, user_id: int, text: str) -> None:
        if self.db is not None:
            import uuid
            await self.db.insert_audit_log(
                log_id=str(uuid.uuid4()),
                event_type="unauthorized_access",
                user_id=user_id,
                details={"command": text},
            )

    # ----- 訊息發送與限流重試 --------------------------------------------- #
    async def send_notification(self, text: str, parse_mode: str = "HTML") -> bool:
        """發送通知，處理速率限制重試。"""
        async def _do_send():
            if self._send_fn is not None:
                await self._send_fn(text)
        return await send_with_retry(_do_send)

    # ----- 授權請求互動 --------------------------------------------------- #
    async def send_authorization_request(
        self, request: AuthorizationRequest
    ) -> str:
        """發送授權請求（Inline Keyboard），回傳 message_id。

        整合階段接真實 Telegram Inline Keyboard；此處記錄請求並回傳佔位 id。
        """
        if self.db is not None:
            await self.db.insert_authorization_request(
                request_id=request.request_id,
                operation_description=request.operation_description,
                target=request.target,
                risk_level=request.risk_level,
                requested_at=request.requested_at.isoformat(),
                expires_at=(request.expires_at or request.requested_at).isoformat(),
            )
        text = (
            f"⚠️ 授權請求\n操作: {request.operation_description}\n"
            f"目標: {request.target}\n風險: {request.risk_level}\n"
            f"[授權] [拒絕]"
        )
        if self._send_fn is not None:
            await self._send_fn(text)
        return f"msg-{request.request_id}"

    async def handle_authorization_callback(
        self, request_id: str, decision: str, decided_by: int
    ) -> None:
        """處理授權按鈕回調，回傳決定至 Authorization_Gate。"""
        decision_enum = (
            AuthorizationDecision.APPROVED if decision == "approve"
            else AuthorizationDecision.DENIED
        )
        if self.db is not None:
            await self.db.update_authorization_decision(
                request_id, decision_enum.value, decided_by=decided_by,
            )
        if self._auth_gate_callback is not None:
            await _maybe_await(
                self._auth_gate_callback(request_id, decision_enum.value)
            )

    async def handle_authorization_timeout(self, request_id: str) -> None:
        """授權逾時（10 分鐘未回應）→ 以逾時拒絕處理。"""
        if self.db is not None:
            await self.db.update_authorization_decision(
                request_id, AuthorizationDecision.TIMEOUT.value,
            )
        if self._auth_gate_callback is not None:
            await _maybe_await(
                self._auth_gate_callback(request_id, AuthorizationDecision.TIMEOUT.value)
            )

    # ----- 純函式 --------------------------------------------------------- #
    def validate_user(self, user_id: int) -> bool:
        return validate_user(user_id, self.whitelist)

    def parse_command(self, text: str) -> Optional[RemoteCommand]:
        return parse_command(text)

    def format_status_reply(self, status: AgentStatus, metrics: dict) -> str:
        return format_status_reply(status, metrics)


# --------------------------------------------------------------------------- #
# 純函式（供 property test 直接驗證）
# --------------------------------------------------------------------------- #
def validate_user(user_id: int, whitelist) -> bool:
    """user_id 在白名單中回傳 True，否則 False。"""
    return user_id in set(whitelist)


def parse_command(text: str) -> Optional[RemoteCommand]:
    """解析指令文字為 RemoteCommand；無法辨識回傳 None。"""
    if not text or not text.strip():
        return None
    parts = text.strip().split()
    cmd_word = parts[0].lower()
    cmd_type = _COMMAND_MAP.get(cmd_word)
    if cmd_type is None:
        return None
    return RemoteCommand(
        command_type=cmd_type,
        args=parts[1:],
        raw_text=text,
    )


def format_status_reply(status: AgentStatus, metrics: dict) -> str:
    """格式化 /status 回覆：含狀態、任務名稱、雙機資源摘要。"""
    state_val = status.state.value if hasattr(status.state, "value") else str(status.state)
    lines = [f"狀態: {state_val}"]
    if status.current_task_name:
        lines.append(
            f"任務: {status.current_task_name} ({status.current_task_progress:.0%})"
        )
    else:
        lines.append("任務: 無")
    # 雙機資源摘要
    for host, m in metrics.items():
        cpu = m.get("cpuPercent", m.get("cpu_percent", 0))
        mem = m.get("memoryPercent", m.get("memory_percent", 0))
        lines.append(f"{host}: CPU {cpu:.0f}% / MEM {mem:.0f}%")
    return "\n".join(lines)


async def send_with_retry(send_fn: Callable, max_retries: int = 3) -> bool:
    """帶限流重試的 Telegram 訊息發送。

    收到 TelegramRateLimitError 時依 retry_after 等待，最多重試 max_retries 次。
    """
    for attempt in range(max_retries + 1):
        try:
            await send_fn()
            return True
        except TelegramRateLimitError as e:
            if attempt < max_retries:
                await asyncio.sleep(e.retry_after)
            else:
                logger.error("Telegram send failed after %d retries", max_retries)
                return False
    return False


async def _maybe_await(value):
    if asyncio.iscoroutine(value):
        return await value
    return value
