"""指數退避重試邏輯。

計算公式：``wait(n) = min(initial_wait * backoff_factor^n, max_wait)``
連續 max_retries 次失敗後，該來源標記為跳過。
"""
from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Optional, TypeVar

from ..models import RetryConfig

T = TypeVar("T")


def compute_backoff(attempt: int, config: RetryConfig) -> float:
    """回傳第 attempt 次重試（0-indexed）的等待秒數。

    wait = min(initial_wait * backoff_factor^attempt, max_wait)
    """
    if attempt < 0:
        raise ValueError("attempt 不可為負")
    wait = config.initial_wait * (config.backoff_factor ** attempt)
    return min(wait, config.max_wait)


class MaxRetriesExceeded(Exception):
    """連續失敗達到上限，來源應被跳過。"""


async def retry_with_backoff(
    operation: Callable[[], Awaitable[T]],
    config: RetryConfig,
    should_retry: Optional[Callable[[Exception], bool]] = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> T:
    """以指數退避重試 operation。

    - operation：無參 async callable
    - should_retry：判斷例外是否應重試（預設全部重試）
    - sleep：注入式睡眠函式（測試可替換為無等待）

    連續失敗達 config.max_retries 次後拋出 MaxRetriesExceeded。
    """
    last_exc: Optional[Exception] = None
    for attempt in range(config.max_retries):
        try:
            return await operation()
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if should_retry is not None and not should_retry(exc):
                raise
            # 最後一次失敗不再等待
            if attempt < config.max_retries - 1:
                await sleep(compute_backoff(attempt, config))
    raise MaxRetriesExceeded(
        f"連續 {config.max_retries} 次失敗，跳過來源"
    ) from last_exc
