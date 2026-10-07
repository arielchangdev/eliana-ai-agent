"""程式碼解析器：Python / Shell / YAML 依函式或區塊切分。"""
from __future__ import annotations

import re

from ...models import FileFormat

# Python：以 def / class 為區塊邊界
_PY_BLOCK_RE = re.compile(r"^(?:async\s+def|def|class)\s+", re.MULTILINE)
# Shell：以 function 定義或 `name()` 為邊界
_SH_BLOCK_RE = re.compile(r"^(?:function\s+\w+|\w+\s*\(\s*\))", re.MULTILINE)


def _split_by_boundary(text: str, boundary: re.Pattern) -> str:
    """依 boundary 起始位置切分，各區塊間以空行分隔。"""
    starts = [m.start() for m in boundary.finditer(text)]
    if not starts:
        return text.strip()
    blocks: list[str] = []
    # 檔案開頭到第一個區塊（imports / 常數）
    if starts[0] > 0:
        head = text[: starts[0]].strip()
        if head:
            blocks.append(head)
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(text)
        block = text[start:end].strip()
        if block:
            blocks.append(block)
    return "\n\n".join(blocks)


def parse_code(content: str, file_format: FileFormat) -> str:
    """依語言將程式碼切分為函式/區塊。

    - Python：以 def / class 邊界切分
    - Shell：以 function 定義切分
    - YAML：以頂層鍵（無縮排）切分
    """
    if file_format == FileFormat.PYTHON:
        return _split_by_boundary(content, _PY_BLOCK_RE)
    if file_format == FileFormat.SHELL:
        return _split_by_boundary(content, _SH_BLOCK_RE)
    if file_format == FileFormat.YAML:
        return _parse_yaml(content)
    return content.strip()


def _parse_yaml(content: str) -> str:
    """以頂層鍵（行首無縮排且含冒號）為區塊邊界。"""
    blocks: list[str] = []
    current: list[str] = []

    def flush() -> None:
        if current:
            block = "\n".join(current).strip()
            if block:
                blocks.append(block)
            current.clear()

    for line in content.splitlines():
        is_top_key = (
            line
            and not line[0].isspace()
            and not line.lstrip().startswith("#")
            and ":" in line
        )
        if is_top_key and current:
            flush()
        current.append(line)
    flush()
    return "\n\n".join(blocks)
