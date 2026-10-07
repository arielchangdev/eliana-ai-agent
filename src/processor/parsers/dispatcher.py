"""解析器分派：依格式將檔案或內容轉為純文字。"""
from __future__ import annotations

from pathlib import Path

from ...models import FileFormat
from .code_parser import parse_code
from .format_detector import UnsupportedFormatError, detect_format
from .html_parser import parse_html
from .markdown_parser import parse_markdown
from .pdf_parser import PdfParseError, parse_pdf


class EmptyContentError(ValueError):
    """內容為空。"""


def parse_file(file_path: str | Path) -> tuple[str, FileFormat]:
    """讀取檔案並依格式解析為純文字。

    回傳 (text, file_format)。無法解析時拋出對應例外：
    - UnsupportedFormatError：格式不支援
    - PdfParseError：PDF 損壞
    - EmptyContentError：內容為空
    """
    path = Path(file_path)
    fmt = detect_format(path)

    if fmt == FileFormat.PDF:
        text = parse_pdf(path)
    else:
        raw = path.read_text(encoding="utf-8", errors="replace")
        text = parse_text_content(raw, fmt)

    if not text or not text.strip():
        raise EmptyContentError("內容為空")
    return text, fmt


def parse_text_content(raw: str, file_format: FileFormat) -> str:
    """依格式解析文字內容（非 PDF）。"""
    if file_format == FileFormat.TXT:
        return raw.strip()
    if file_format == FileFormat.MARKDOWN:
        return parse_markdown(raw)
    if file_format == FileFormat.HTML:
        return parse_html(raw)
    if file_format in (FileFormat.PYTHON, FileFormat.SHELL, FileFormat.YAML):
        return parse_code(raw, file_format)
    raise UnsupportedFormatError(f"檔案格式不支援: {file_format}")


__all__ = [
    "parse_file",
    "parse_text_content",
    "EmptyContentError",
    "UnsupportedFormatError",
    "PdfParseError",
    "detect_format",
]
