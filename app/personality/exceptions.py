"""自訂例外類別。"""
from __future__ import annotations


class PersonalityError(Exception):
    """人格模組基礎例外。"""


class ValidationError(PersonalityError):
    """人格設定驗證失敗。"""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors) if errors else "驗證失敗")


class EvolutionThresholdError(PersonalityError):
    """演化累計變化達到閾值。"""

    def __init__(self, parameter_path: str, cumulative_percent: float):
        self.parameter_path = parameter_path
        self.cumulative_percent = cumulative_percent
        super().__init__(
            f"參數 {parameter_path} 累計變化 {cumulative_percent:.1f}% 已達閾值"
        )


class RateLimitExceededError(PersonalityError):
    """超出每日社群互動限制。"""

    def __init__(self, platform: str, daily_count: int):
        self.platform = platform
        self.daily_count = daily_count
        super().__init__(
            f"平台 {platform} 今日互動 {daily_count} 次，已達每日上限"
        )


class VersionNotFoundError(PersonalityError):
    """回溯目標版本不存在。"""

    def __init__(self, version_id: str):
        self.version_id = version_id
        super().__init__(f"版本不存在: {version_id}")
