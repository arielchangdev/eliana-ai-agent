"""錯誤處理類別。"""
from __future__ import annotations


class DashboardError(Exception):
    """Dashboard 模組錯誤基底類。"""

    def __init__(self, message: str, severity: str = "MEDIUM", retryable: bool = False):
        self.message = message
        self.severity = severity
        self.retryable = retryable
        super().__init__(message)


class TelegramRateLimitError(DashboardError):
    """Telegram API 限流錯誤（HTTP 429）。"""

    def __init__(self, retry_after: int):
        super().__init__(
            f"Rate limited, retry after {retry_after}s",
            severity="MEDIUM", retryable=True,
        )
        self.retry_after = retry_after


class DataSourceUnavailableError(DashboardError):
    """資料來源不可用。"""

    def __init__(self, source: str):
        super().__init__(
            f"Data source unavailable: {source}",
            severity="HIGH", retryable=True,
        )
        self.source = source


class UnauthorizedAccessError(DashboardError):
    """未授權存取（安全事件）。"""

    def __init__(self, user_id: int, command: str):
        super().__init__(
            f"Unauthorized access from user {user_id}: {command}",
            severity="SECURITY", retryable=False,
        )
        self.user_id = user_id
        self.command = command
