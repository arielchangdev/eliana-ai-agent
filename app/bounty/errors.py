"""Bounty 模組錯誤處理類別。

包含 BountyError 基底類及所有子類別：PlatformCrawlError、
RateLimitError、ScopeViolationError、ScanTimeoutError、
AuthorizationTimeoutError、ReportGenerationError、ToolOutputParseError。
"""

from app.bounty.enums import PlatformType, ScanTool


class BountyError(Exception):
    """Bounty 模組錯誤基底類。"""

    def __init__(self, message: str, severity: str, retryable: bool = False):
        self.message = message
        self.severity = severity
        self.retryable = retryable
        super().__init__(message)


class PlatformCrawlError(BountyError):
    """平台爬取錯誤。"""

    def __init__(self, message: str, platform: PlatformType, status_code: int):
        super().__init__(message, severity="MEDIUM", retryable=True)
        self.platform = platform
        self.status_code = status_code


class RateLimitError(BountyError):
    """速率限制錯誤。"""

    def __init__(self, platform: PlatformType, retry_after: float = 60.0):
        super().__init__(f"Rate limited by {platform.value}", severity="LOW", retryable=True)
        self.retry_after = retry_after


class ScopeViolationError(BountyError):
    """範圍違規錯誤（不可重試）。"""

    def __init__(self, target: str, program_id: str):
        super().__init__(
            f"Target {target} is out of scope for program {program_id}",
            severity="CRITICAL", retryable=False
        )
        self.target = target
        self.program_id = program_id


class ScanTimeoutError(BountyError):
    """掃描逾時錯誤。"""

    def __init__(self, scan_id: str, tool: ScanTool, timeout_seconds: float):
        super().__init__(
            f"Scan {scan_id} tool {tool.value} timed out after {timeout_seconds}s",
            severity="MEDIUM", retryable=False
        )
        self.scan_id = scan_id
        self.tool = tool


class AuthorizationTimeoutError(BountyError):
    """授權逾時錯誤。"""

    def __init__(self, operation_id: str):
        super().__init__(
            f"Authorization for {operation_id} expired after 24h",
            severity="LOW", retryable=False
        )
        self.operation_id = operation_id


class ReportGenerationError(BountyError):
    """報告生成錯誤。"""

    def __init__(self, message: str, vulnerability_id: str):
        super().__init__(message, severity="MEDIUM", retryable=True)
        self.vulnerability_id = vulnerability_id


class ToolOutputParseError(BountyError):
    """工具輸出解析錯誤。"""

    def __init__(self, tool: ScanTool, raw_output: str):
        super().__init__(
            f"Failed to parse {tool.value} output",
            severity="MEDIUM", retryable=False
        )
        self.tool = tool
        self.raw_output = raw_output
