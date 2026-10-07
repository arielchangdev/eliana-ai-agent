"""遠端指令執行相關資料模型."""

from dataclasses import dataclass


@dataclass
class RemoteResult:
    """遠端指令執行結果。"""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    execution_time_ms: float = 0.0
