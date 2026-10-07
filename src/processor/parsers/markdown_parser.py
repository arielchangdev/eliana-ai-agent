"""Markdown 解析器：依標題層級切分為段落區塊。"""
from __future__ import annotations

import re

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")


def parse_markdown(content: str) -> str:
    """將 Markdown 依標題層級整理為以空行分隔的區塊純文字。

    保留標題文字作為區塊起始，移除多餘的 Markdown 標記符號，
    輸出以 ``\n\n`` 分隔的區塊供 chunker 使用。
    """
    blocks: list[str] = []
    current: list[str] = []

    def flush() -> None:
        if current:
            block = "\n".join(current).strip()
            if block:
                blocks.append(block)
            current.clear()

    for line in content.splitlines():
        heading = _HEADING_RE.match(line.strip())
        if heading:
            # 標題開啟新區塊
            flush()
            current.append(heading.group(2).strip())
        else:
            current.append(line)
    flush()

    return "\n\n".join(blocks)
