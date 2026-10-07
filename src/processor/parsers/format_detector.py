"""依副檔名偵測檔案格式。"""
from __future__ import annotations

from pathlib import Path

from ...models import FileFormat

# 副檔名 -> FileFormat 對照
_EXT_MAP: dict[str, FileFormat] = {
    ".txt": FileFormat.TXT,
    ".text": FileFormat.TXT,
    ".md": FileFormat.MARKDOWN,
    ".markdown": FileFormat.MARKDOWN,
    ".pdf": FileFormat.PDF,
    ".html": FileFormat.HTML,
    ".htm": FileFormat.HTML,
    ".py": FileFormat.PYTHON,
    ".sh": FileFormat.SHELL,
    ".bash": FileFormat.SHELL,
    ".yaml": FileFormat.YAML,
    ".yml": FileFormat.YAML,
}


class UnsupportedFormatError(ValueError):
    """不支援的檔案格式。"""


def detect_format(file_path: str | Path) -> FileFormat:
    """依副檔名判斷格式，無法辨識時拋出 UnsupportedFormatError。"""
    ext = Path(file_path).suffix.lower()
    fmt = _EXT_MAP.get(ext)
    if fmt is None:
        raise UnsupportedFormatError(f"檔案格式不支援: {ext or '(無副檔名)'}")
    return fmt
