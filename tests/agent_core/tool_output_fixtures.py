"""Loader helper for the real-shaped tool-output fixtures (live-wiring Task 3).

The fixture files under ``fixtures/tool_output/`` are **hand-crafted** samples
(NOT reused from an existing corpus — the repo had none). Each sample was built
from the actual field expectations of the corresponding parser in
``app/bounty/scanner.py`` (e.g. nmap ``<port portid=.. ><state state="open"/>``,
nuclei JSONL ``info.severity``/``matched-at``, nikto ``^\\+ .. : ..`` lines).
Because the agent path and the legacy path parse the *same fixture bytes*, the
equivalence test (Task 4.3) remains a meaningful anti-drift guard.

For every one of the 8 auto-orchestration tools there are three variants:
  * ``<tool>.finding.<ext>``   — real, findings-bearing output
  * ``<tool>.empty.<ext>``     — whitespace-only (honest-empty case)
  * ``<tool>.malformed.<ext>`` — garbage / unparseable output

Loader helpers return the raw text so both parser and equivalence tests share
exactly the same input.
"""
from __future__ import annotations

import os
from typing import Iterator

from app.bounty.enums import ScanTool

_FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "tool_output")

# tool -> file extension used for its fixtures
_TOOL_EXT: dict[ScanTool, str] = {
    ScanTool.NMAP: "xml",
    ScanTool.NUCLEI: "jsonl",
    ScanTool.NIKTO: "txt",
    ScanTool.WHATWEB: "json",
    ScanTool.WAFW00F: "txt",
    ScanTool.DNSRECON: "txt",
    ScanTool.SSLSCAN: "txt",
    ScanTool.GOBUSTER: "txt",
}

# The 8 tools the agent may auto-orchestrate (mirror scanner._AUTO_ORCHESTRATION_TOOLS).
FIXTURE_TOOLS: tuple[ScanTool, ...] = tuple(_TOOL_EXT.keys())


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def fixture_path(tool: ScanTool, variant: str = "finding") -> str:
    ext = _TOOL_EXT[tool]
    return os.path.join(_FIXTURE_DIR, f"{tool.value}.{variant}.{ext}")


def load_fixture(tool: ScanTool, variant: str = "finding") -> str:
    """Return the raw text of a tool-output fixture.

    variant is one of: "finding", "empty", "malformed".
    """
    return _read(fixture_path(tool, variant))


def iter_finding_fixtures() -> Iterator[tuple[ScanTool, str]]:
    """Yield (tool, raw_text) for each tool's findings-bearing fixture."""
    for tool in FIXTURE_TOOLS:
        yield tool, load_fixture(tool, "finding")
