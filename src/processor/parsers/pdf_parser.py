"""PDF 解析器：使用 PyMuPDF 萃取文字與頁碼。"""
from __future__ import annotations

from pathlib import Path


class PdfParseError(ValueError):
    """PDF 無法解析（損壞或格式錯誤）。"""


def parse_pdf(file_path: str | Path) -> str:
    """萃取 PDF 全文，各頁以頁碼標記分隔。

    以串流方式逐頁讀取以降低記憶體用量。PyMuPDF 於函式內
    lazy import，缺少相依時給出明確錯誤。
    """
    # PyMuPDF 新版建議 `import pymupdf`，舊版為 `import fitz`。
    # 優先使用新名稱，回退舊名稱以相容不同版本（含 RHEL 上的版本）。
    try:
        import pymupdf as fitz
    except ImportError:
        try:
            import fitz  # 舊版 PyMuPDF
        except ImportError as exc:  # pragma: no cover - 環境相依
            raise PdfParseError(
                "PDF 解析需要 PyMuPDF (pymupdf)，請先安裝該套件"
            ) from exc

    path = Path(file_path)
    if not path.exists():
        raise PdfParseError(f"檔案不存在: {path}")

    parts: list[str] = []
    try:
        with fitz.open(str(path)) as doc:
            for page_index in range(doc.page_count):
                page = doc.load_page(page_index)
                text = page.get_text("text")
                if text.strip():
                    parts.append(f"[Page {page_index + 1}]\n{text.strip()}")
    except Exception as exc:  # fitz 對損壞檔案拋出各式例外
        raise PdfParseError("檔案損壞，無法解析") from exc

    return "\n\n".join(parts)
