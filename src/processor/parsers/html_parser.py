"""HTML 解析器：以 regex 去除標籤保留文本。"""
from __future__ import annotations

import html
import re

# 移除 script/style 區塊（含內容）
_SCRIPT_STYLE_RE = re.compile(
    r"<(script|style)\b[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL
)
# 區塊級標籤轉為換行，以保留段落結構
_BLOCK_RE = re.compile(
    r"</?(p|div|br|section|article|h[1-6]|li|tr|table|ul|ol)\b[^>]*>",
    re.IGNORECASE,
)
# 移除其餘標籤
_TAG_RE = re.compile(r"<[^>]+>")
# 收斂多餘空行
_MULTI_NL_RE = re.compile(r"\n{3,}")
_MULTI_SPACE_RE = re.compile(r"[ \t]{2,}")


def parse_html(content: str) -> str:
    """去除 HTML 標籤，保留可讀文本與段落換行。"""
    text = _SCRIPT_STYLE_RE.sub(" ", content)
    text = _BLOCK_RE.sub("\n", text)
    text = _TAG_RE.sub("", text)
    text = html.unescape(text)
    text = _MULTI_SPACE_RE.sub(" ", text)
    text = _MULTI_NL_RE.sub("\n\n", text)
    # 逐行去除前後空白後重組
    lines = [ln.strip() for ln in text.splitlines()]
    text = "\n".join(ln for ln in lines if ln != "" or True)
    return text.strip()
