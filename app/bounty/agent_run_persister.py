"""AgentRunPersister — persist an agent-driven assessment run into bounty.db.

Design D3/D4 (eliana-agent-live-wiring): the agent path does NOT call
``AuthorizedScanner.scan`` (that would re-run the fixed phased profile and
defeat planner-driven tool selection). Instead this thin persister REUSES the
same persistence primitives the legacy path already uses:

  * the identical ``scans`` / ``vulnerabilities`` column layout
    ``ScanEngine.execute_scan`` writes (so the existing dashboard queries work
    unchanged), and
  * the existing report path (``AuthorizedScanner._ensure_manual_program`` /
    ``_fetch_program`` / ``ReportGenerator`` / ``should_generate_report`` /
    ``_persist_report``) for MEDIUM+ findings.

No parser / dedup / report logic is reimplemented here — it is delegated.

Agent origin marker (no schema migration): the ``scans`` table has no dedicated
origin column, but it has a pre-existing nullable ``profile TEXT DEFAULT '{}'``
column that ``execute_scan`` never writes. We store ``{"origin": "agent"}`` there
so the dashboard can distinguish agent runs from legacy runs without a migration.

Honesty: a db failure RAISES (and is logged) — it never silently drops or
fabricates findings. The agent findings surfaced to the planner are projections
(severity + ATT&CK label + non-sensitive identifying fields only); the
reassembled ``Vulnerability`` rows therefore carry empty ``evidence`` /
``raw_output`` — which is honest, because the agent path deliberately kept raw
payloads out of the planner-facing surface.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

import structlog

from app.bounty.enums import ScanTool, SeverityLevel
from app.bounty.models import Vulnerability
from app.bounty.scanner import deduplicate_findings
from app.bounty.authorized_scan import AuthorizedScanner

logger = structlog.get_logger(__name__)

# Marker written into scans.profile so agent runs are distinguishable from
# legacy runs without a schema change.
AGENT_ORIGIN_MARKER = {"origin": "agent"}


def _coerce_severity(value) -> SeverityLevel:
    """Best-effort map a projected severity (a SeverityLevel or its .value str)
    back to the SeverityLevel enum. Unknown -> INFO (honest, never upgrades)."""
    if isinstance(value, SeverityLevel):
        return value
    try:
        return SeverityLevel(str(value).lower())
    except (ValueError, KeyError):
        return SeverityLevel.INFO


def _coerce_tool(value) -> ScanTool:
    """Map a projected tool (a ScanTool or its .value str) back to ScanTool.
    Unknown -> NUCLEI (the Vulnerability model's default tool_source)."""
    if isinstance(value, ScanTool):
        return value
    try:
        return ScanTool(str(value).lower())
    except (ValueError, KeyError):
        return ScanTool.NUCLEI


def reassemble_vulnerability(finding: dict) -> Vulnerability:
    """Rebuild a Vulnerability from an agent-path projected finding dict.

    The projection carries severity + title + affected_endpoint + tool + ATT&CK
    labels only. ``evidence`` / ``raw_output`` / ``description`` are intentionally
    absent (they were never surfaced to the planner) and remain empty here —
    honest, not fabricated."""
    return Vulnerability(
        severity=_coerce_severity(finding.get("severity")),
        title=finding.get("title", "") or "",
        description=finding.get("description", "") or "",
        affected_endpoint=finding.get("affected_endpoint", "") or "",
        tool_source=_coerce_tool(finding.get("tool")),
        attack_technique_id=finding.get("attack_technique_id"),
        attack_technique_name=finding.get("attack_technique_name"),
        attack_tactic=finding.get("attack_tactic"),
    )


class AgentRunPersister:
    """Persist an ``AssessmentOutcome`` from a planner-driven run to bounty.db,
    reusing the legacy schema, primitives, and report path."""

    def __init__(self, db_path: str = "data/bounty.db", report_llm=None,
                 assessment_memory=None) -> None:
        self._db_path = db_path
        self._report_llm = report_llm
        # Reuse the AuthorizedScanner's report helpers (ensure-program, fetch-
        # program, generate+persist reports). We do NOT call its .scan().
        self._reporter = AuthorizedScanner(
            db_path=db_path, scan_engine=None, report_llm=report_llm,
            assessment_memory=assessment_memory)

    async def persist(self, outcome) -> str:
        """Write a scans row + vulnerabilities rows for this agent run and
        generate reports for MEDIUM+ findings. Returns the scan_id.

        Reuses the same bounty.db schema and report path as AuthorizedScanner.
        On db failure, raises (and logs) — never silently drops or fabricates.
        """
        import aiosqlite

        scan_id = str(uuid.uuid4())
        goal = getattr(getattr(outcome, "trace", None), "goal", None)
        target_url = getattr(goal, "target_url", "") or ""
        # Normalize to the host the legacy path stores (scheme stripped), so the
        # dashboard groups agent + legacy rows for the same target consistently.
        scan_host = target_url.split("://")[-1].split("/")[0] if target_url else ""

        # Reassemble real Vulnerability objects from the projected findings and
        # dedup across the FULL run (REUSE legacy dedup) — matches execute_scan's
        # finalization over multiple tools.
        findings = list(getattr(outcome, "findings", []) or [])
        vulns = [reassemble_vulnerability(f) for f in findings]
        vulns = deduplicate_findings(vulns)

        started_at = datetime.now(timezone.utc)
        completed_at = started_at

        try:
            async with aiosqlite.connect(self._db_path) as conn:
                # program_id is a NOT NULL FK -> bounty_programs(id); ensure the
                # 'manual' program row exists (reuses AuthorizedScanner helper).
                await self._reporter._ensure_manual_program(conn)

                # scans row — identical columns to execute_scan's INSERT, plus
                # the origin marker in the pre-existing nullable `profile` column
                # (no schema migration).
                await conn.execute(
                    "INSERT INTO scans (id, program_id, target_url, target_type,"
                    " status, profile, started_at, completed_at, duration_seconds)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, "manual", scan_host, "web_app",
                     "completed", json.dumps(AGENT_ORIGIN_MARKER),
                     started_at.isoformat(), completed_at.isoformat(), 0.0),
                )

                # vulnerabilities rows — identical column layout to execute_scan.
                for v in vulns:
                    v.scan_id = scan_id
                    await conn.execute(
                        "INSERT INTO vulnerabilities"
                        " (id, scan_id, cve_id, severity, title, description,"
                        " affected_endpoint, evidence, tool_source, raw_output,"
                        " discovered_at, attack_technique_id,"
                        " attack_technique_name, attack_tactic)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (v.id, scan_id, v.cve_id, v.severity.value,
                         v.title, v.description, v.affected_endpoint,
                         v.evidence, v.tool_source.value, v.raw_output,
                         v.discovered_at.isoformat(),
                         getattr(v, "attack_technique_id", None),
                         getattr(v, "attack_technique_name", None),
                         getattr(v, "attack_tactic", None)),
                    )
                await conn.commit()

                # Reports for MEDIUM+ findings — REUSE the legacy report path on
                # the SAME connection (reports.vulnerability_id FK ->
                # vulnerabilities, which we just wrote above).
                result = _ReassembledResult(scan_id=scan_id, vulnerabilities=vulns)
                await self._reporter._generate_reports(result, conn)
                await conn.commit()
        except Exception as exc:  # noqa: BLE001 - must be LOUD, never silent
            logger.error("agent_run_persist_failed", scan_id=scan_id,
                         target=scan_host, error=str(exc))
            raise

        logger.info("agent_run_persisted", scan_id=scan_id, target=scan_host,
                    findings=len(vulns), origin="agent")
        return scan_id


class _ReassembledResult:
    """Minimal ScanResult-shaped carrier for _generate_reports (it only reads
    ``.vulnerabilities``). Not a persisted model — just the shape the reused
    report helper expects."""

    def __init__(self, scan_id: str, vulnerabilities: list) -> None:
        self.scan_id = scan_id
        self.vulnerabilities = vulnerabilities
