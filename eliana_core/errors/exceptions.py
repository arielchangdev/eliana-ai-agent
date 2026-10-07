"""Eliana Core 自定義錯誤類別。"""


class InfraError(Exception):
    """基礎設施錯誤基底類。"""

    def __init__(self, message: str, severity: str, retryable: bool = False):
        self.message = message
        self.severity = severity
        self.retryable = retryable
        super().__init__(message)


class SSHConnectionError(InfraError):
    """SSH 連線錯誤。"""

    def __init__(self, message: str):
        super().__init__(message, severity="HIGH", retryable=True)


class SSHAuthenticationError(InfraError):
    """SSH 認證錯誤（不可重試）。"""

    def __init__(self, message: str):
        super().__init__(message, severity="CRITICAL", retryable=False)


class TaskExecutionError(InfraError):
    """任務執行錯誤。"""

    def __init__(self, message: str, task_id: str):
        super().__init__(message, severity="MEDIUM", retryable=True)
        self.task_id = task_id


class ResourceExhaustedError(InfraError):
    """資源耗盡錯誤。"""

    def __init__(self, message: str, resource_type: str):
        super().__init__(message, severity="HIGH", retryable=True)
        self.resource_type = resource_type
