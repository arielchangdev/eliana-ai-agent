"""簡易 token 計算工具。

為避免對特定 LLM tokenizer 的硬相依，採用穩定且確定性的近似規則：
以空白與常見標點切分為 token。此規則在 chunker 與 processor 間保持一致，
確保 token_count 的可預測性（供 Property 3/6 驗證）。
"""
from __future__ import annotations

import re

# 將連續非空白視為 token，並將標點獨立為 token
_TOKEN_RE = re.compile(r"\w+|[^\w\s]", re.UNICODE)


def count_tokens(text: str) -> int:
    """回傳文本的 token 數。"""
    if not text:
        return 0
    return len(_TOKEN_RE.findall(text))


def tokenize(text: str) -> list[str]:
    """回傳 token 列表。"""
    return _TOKEN_RE.findall(text)
