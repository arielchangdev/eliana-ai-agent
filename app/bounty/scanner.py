"""Bounty module vulnerability scan engine.

Implements ScanEngine class for coordinating multiple scan tools on authorized targets.
Includes select_profile, is_target_in_scope pure functions, and four tool output parsers.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional, Protocol
from urllib.parse import urlparse

import defusedxml.ElementTree as ET

from app.bounty.enums import ScanStatus, ScanTool, SeverityLevel, TargetType
from app.bounty.errors import ScanTimeoutError, ToolOutputParseError
from app.bounty.models import (
    DEFAULT_PROFILES,
    ProgramScope,
    ScanProfile,
    ScanProgress,
    ScanResult,
    ScanTarget,
    Vulnerability,
)

if TYPE_CHECKING:
    import aiosqlite

    from eliana_core.services.ssh_channel import SSHChannel

logger = logging.getLogger(__name__)

# nuclei severity mapping
_NUCLEI_SEVERITY_MAP: dict[str, SeverityLevel] = {
    "critical": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "info": SeverityLevel.INFO,
}

_PROGRESS_REPORT_INTERVAL: float = 30.0
_DEFAULT_TOOL_TIMEOUT: float = 1800.0

_TOOL_COMMANDS: dict[ScanTool, str] = {
    ScanTool.NMAP: "nmap",
    ScanTool.NIKTO: "nikto",
    ScanTool.NUCLEI: "nuclei",
    ScanTool.SQLMAP: "sqlmap",
}


def select_profile(target: ScanTarget) -> ScanProfile:
    """Select scan profile based on target type (pure function)."""
    tools = DEFAULT_PROFILES.get(target.target_type, [])
    return ScanProfile(tools=list(tools))


def is_target_in_scope(target: str, scope: ProgramScope) -> bool:
    """Validate target URL is within the authorized scope (pure function)."""
    if not scope.domains:
        return False
    try:
        parsed = urlparse(target)
        hostname = parsed.hostname
        path = parsed.path or "/"
    except Exception:
        return False
    if not hostname:
        return False
    hostname = hostname.lower()
    domain_match = False
    for scope_domain in scope.domains:
        scope_domain_lower = scope_domain.lower()
        if scope_domain_lower.startswith("*."):
            base_domain = scope_domain_lower[2:]
            if hostname == base_domain or hostname.endswith("." + base_domain):
                domain_match = True
                break
        else:
            if hostname == scope_domain_lower:
                domain_match = True
                break
    if not domain_match:
        return False
    for excluded in scope.excluded_paths:
        if excluded.endswith("*"):
            prefix = excluded[:-1]
            if path.startswith(prefix):
                return False
        elif excluded.endswith("/"):
            if path == excluded or path.startswith(excluded):
                return False
        else:
            if path == excluded:
                return False
    return True


# --- Tool output parsers ---


def parse_nmap_xml(xml_content: str) -> list[Vulnerability]:
    """Parse nmap XML output into unified vulnerability format."""
    vulns: list[Vulnerability] = []
    if not xml_content or not xml_content.strip():
        return vulns
    try:
        root = ET.fromstring(xml_content)
    except Exception:
        raise ToolOutputParseError(tool=ScanTool.NMAP, raw_output=xml_content[:500])
    for host in root.findall(".//host"):
        addr_elem = host.find("address")
        if addr_elem is None:
            continue
        addr = addr_elem.get("addr", "unknown")
        for port_elem in host.findall(".//port"):
            port_id = port_elem.get("portid", "")
            protocol = port_elem.get("protocol", "tcp")
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue
            service_elem = port_elem.find("service")
            service_name = service_elem.get("name", "") if service_elem is not None else ""
            for script in port_elem.findall(".//script"):
                script_id = script.get("id", "")
                script_output = script.get("output", "")
                severity = _nmap_script_severity(script_id)
                cve_id = None
                cve_match = re.search(r"(CVE-\d{4}-\d+)", script_output)
                if cve_match:
                    cve_id = cve_match.group(1)
                vulns.append(Vulnerability(
                    cve_id=cve_id,
                    severity=severity,
                    title=f"nmap/{script_id} on {addr}:{port_id}",
                    description=script_output[:500],
                    affected_endpoint=f"{addr}:{port_id}/{protocol}",
                    evidence=script_output,
                    tool_source=ScanTool.NMAP,
                    raw_output=script_output,
                ))
            if not port_elem.findall(".//script"):
                vulns.append(Vulnerability(
                    severity=SeverityLevel.INFO,
                    title=f"Open port {port_id}/{protocol} ({service_name}) on {addr}",
                    description=f"Service: {service_name}",
                    affected_endpoint=f"{addr}:{port_id}/{protocol}",
                    evidence=f"Port {port_id} is open",
                    tool_source=ScanTool.NMAP,
                    raw_output="",
                ))
    return vulns


def _nmap_script_severity(script_id: str) -> SeverityLevel:
    """Determine severity based on nmap script ID."""
    sid = script_id.lower()
    if any(kw in sid for kw in ("vulners", "exploit", "brute")):
        return SeverityLevel.HIGH
    if any(kw in sid for kw in ("ssl-heartbleed", "smb-vuln", "http-vuln")):
        return SeverityLevel.MEDIUM
    return SeverityLevel.LOW


def parse_nuclei_json(json_content: str) -> list[Vulnerability]:
    """Parse nuclei JSONL output into unified vulnerability format."""
    vulns: list[Vulnerability] = []
    if not json_content or not json_content.strip():
        return vulns
    for line in json_content.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError:
            continue
        template_id = finding.get("template-id", finding.get("templateID", ""))
        info = finding.get("info", {})
        severity_str = info.get("severity", "info").lower()
        severity = _NUCLEI_SEVERITY_MAP.get(severity_str, SeverityLevel.INFO)
        name = info.get("name", template_id)
        description = info.get("description", "")
        matched_at = finding.get("matched-at", finding.get("matchedAt", ""))
        cve_id = None
        classification = info.get("classification", {})
        cve_ids = classification.get("cve-id", [])
        if cve_ids and isinstance(cve_ids, list) and len(cve_ids) > 0:
            cve_id = cve_ids[0]
        vulns.append(Vulnerability(
            cve_id=cve_id, severity=severity,
            title=f"[{template_id}] {name}",
            description=description[:500], affected_endpoint=matched_at,
            evidence=line[:1000], tool_source=ScanTool.NUCLEI, raw_output=line,
        ))
    return vulns


def parse_nikto_output(output: str) -> list[Vulnerability]:
    """Parse nikto text output into unified vulnerability format."""
    vulns: list[Vulnerability] = []
    if not output or not output.strip():
        return vulns
    finding_pattern = re.compile(r"^\+\s+(?:OSVDB-(\d+):\s+)?(.+?):\s+(.+)", re.MULTILINE)
    target_pattern = re.compile(r"^\+\s+Target IP:\s+(.+)", re.MULTILINE)
    target_match = target_pattern.search(output)
    target_ip = target_match.group(1).strip() if target_match else "unknown"
    for match in finding_pattern.finditer(output):
        osvdb_id = match.group(1)
        path_or_header = match.group(2).strip()
        desc = match.group(3).strip()
        skip_kw = ["target ip", "target hostname", "target port", "start time", "end time", "host(s) tested"]
        if any(s in path_or_header.lower() for s in skip_kw):
            continue
        severity = _nikto_severity(desc, osvdb_id)
        vulns.append(Vulnerability(
            severity=severity, title=f"nikto: {desc[:80]}",
            description=desc,
            affected_endpoint=path_or_header if path_or_header.startswith("/") else target_ip,
            evidence=match.group(0), tool_source=ScanTool.NIKTO, raw_output=match.group(0),
        ))
    return vulns


def _nikto_severity(description: str, osvdb_id: Optional[str]) -> SeverityLevel:
    """Determine nikto finding severity."""
    dl = description.lower()
    if any(kw in dl for kw in ("remote code", "rce", "command injection")):
        return SeverityLevel.CRITICAL
    if any(kw in dl for kw in ("sql injection", "xss", "cross-site", "directory traversal", "lfi", "rfi")):
        return SeverityLevel.HIGH

    if any(kw in dl for kw in ("information disclosure", "version", "outdated", "default")):
        return SeverityLevel.MEDIUM
    if osvdb_id:
        return SeverityLevel.LOW
    return SeverityLevel.INFO


def parse_sqlmap_output(output: str) -> list[Vulnerability]:
    """Parse sqlmap text output into unified vulnerability format."""
    vulns: list[Vulnerability] = []
    if not output or not output.strip():
        return vulns
    injection_block = re.compile(r"Type:\s+(.+?)\n\s+Title:\s+(.+?)\n\s+Payload:\s+(.+?)(?:\n|$)", re.MULTILINE)
    url_pattern = re.compile(r"URL:\s+(https?://\S+)", re.MULTILINE)
    url_match = url_pattern.search(output)
    target_url = url_match.group(1) if url_match else "unknown"
    vuln_confirm = re.compile(r"Parameter:\s+'?([^']+?)'?\s+is vulnerable", re.MULTILINE | re.IGNORECASE)
    # Find parameter context
    param_pattern = re.compile(r"Parameter:\s+(\S+)", re.MULTILINE)
    param_match = param_pattern.search(output)
    param_name = param_match.group(1) if param_match else ""

    for match in injection_block.finditer(output):
        inject_type = match.group(1).strip()
        title = match.group(2).strip()
        payload = match.group(3).strip()
        severity = _sqlmap_severity(inject_type)
        evidence_str = f"Parameter: {param_name}\nPayload: {payload}" if param_name else f"Payload: {payload}"
        vulns.append(Vulnerability(
            severity=severity, title=f"sqlmap: {title}",
            description=f"SQL Injection ({inject_type})", affected_endpoint=target_url,
            evidence=evidence_str, tool_source=ScanTool.SQLMAP, raw_output=match.group(0),
        ))
    if not vulns:
        for match in vuln_confirm.finditer(output):
            param = match.group(1).strip()
            vulns.append(Vulnerability(
                severity=SeverityLevel.HIGH,
                title=f"sqlmap: SQL Injection in parameter '{param}'",
                description=f"Parameter '{param}' is vulnerable to SQL injection",
                affected_endpoint=target_url, evidence=match.group(0),
                tool_source=ScanTool.SQLMAP, raw_output=match.group(0),
            ))
    return vulns


def _sqlmap_severity(inject_type: str) -> SeverityLevel:
    """Determine sqlmap injection severity."""
    il = inject_type.lower()
    if "stacked" in il or "out-of-band" in il:
        return SeverityLevel.CRITICAL
    if "union" in il or "error-based" in il:
        return SeverityLevel.CRITICAL
    if "blind" in il or "time-based" in il:
        return SeverityLevel.HIGH
    return SeverityLevel.MEDIUM


class ScanEngine:
    """Vulnerability scan engine that coordinates tools on Weapon_Host via SSH."""

    def __init__(self, ssh_channel: Optional["SSHChannel"] = None, db: Optional["aiosqlite.Connection"] = None):
        """Initialize ScanEngine with SSH channel and optional DB connection."""
        self._ssh = ssh_channel
        self._db = db
        self._progress_store: dict[str, ScanProgress] = {}

    async def run_tool(
        self, tool: ScanTool, target: str, args: list[str], timeout: float = _DEFAULT_TOOL_TIMEOUT
    ) -> str:
        """Execute a single scan tool on Weapon_Host via SSH_Channel.

        Args:
            tool: The scan tool to execute (NMAP, NIKTO, NUCLEI, SQLMAP).
            target: Target URL or IP address.
            args: Additional command-line arguments for the tool.
            timeout: Maximum execution time in seconds (default 1800 = 30 min).

        Returns:
            Raw string output from the tool (stdout).

        Raises:
            ScanTimeoutError: If execution exceeds the timeout.
        """
        base_cmd = _TOOL_COMMANDS[tool]
        cmd_parts = [base_cmd] + args + [target]
        command = " ".join(cmd_parts)
        logger.info("Running tool %s on target %s (timeout=%.0fs)", tool.value, target, timeout)
        result = await self._ssh.execute_remote(command, timeout=timeout)
        # exit_code -1 with stderr indicates timeout from SSH channel
        if result.exit_code == -1 and result.stderr:
            raise ScanTimeoutError(scan_id="", tool=tool, timeout_seconds=timeout)
        if result.stderr:
            logger.warning("Tool %s stderr: %s", tool.value, result.stderr[:500])
        return result.stdout

    async def report_progress(self, scan_id: str, progress: ScanProgress) -> None:
        """Report scan progress. Called every 30 seconds during execution.

        Stores progress in memory and persists to database if available.
        """
        progress.scan_id = scan_id
        progress.updated_at = datetime.now(timezone.utc)
        self._progress_store[scan_id] = progress
        logger.info(
            "Scan %s progress: %.1f%% complete, %d vulns, ~%.0fs remaining, tool=%s",
            scan_id, progress.percent_complete, progress.vulnerabilities_found,
            progress.estimated_remaining_seconds,
            progress.current_tool.value if progress.current_tool else "none",
        )
        if self._db is not None:
            try:
                await self._db.execute(
                    "INSERT OR REPLACE INTO scan_progress"
                    " (scan_id, percent_complete, vulnerabilities_found,"
                    " estimated_remaining_seconds, current_tool, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (scan_id, progress.percent_complete, progress.vulnerabilities_found,
                     progress.estimated_remaining_seconds,
                     progress.current_tool.value if progress.current_tool else None,
                     progress.updated_at.isoformat()),
                )
                await self._db.commit()
            except Exception as e:
                logger.warning("Failed to persist progress: %s", e)

    def get_progress(self, scan_id: str) -> Optional[ScanProgress]:
        """Get the latest progress for a scan from in-memory store."""
        return self._progress_store.get(scan_id)

    def parse_nmap_xml(self, xml_content: str) -> list[Vulnerability]:
        """Parse nmap XML output (delegates to module-level parser)."""
        return parse_nmap_xml(xml_content)

    def parse_nuclei_json(self, json_content: str) -> list[Vulnerability]:
        """Parse nuclei JSON output (delegates to module-level parser)."""
        return parse_nuclei_json(json_content)

    def parse_nikto_output(self, output: str) -> list[Vulnerability]:
        """Parse nikto text output (delegates to module-level parser)."""
        return parse_nikto_output(output)

    def parse_sqlmap_output(self, output: str) -> list[Vulnerability]:
        """Parse sqlmap text output (delegates to module-level parser)."""
        return parse_sqlmap_output(output)

    async def execute_scan(self, target: ScanTarget, profile: ScanProfile) -> ScanResult:
        """Execute a full scan against the target using the given profile.

        Orchestrates: create scan record, run each tool with progress reporting,
        parse outputs, handle timeouts, persist results.
        """
        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc)
        all_vulnerabilities: list[Vulnerability] = []
        tools_used: list[ScanTool] = []
        final_status = ScanStatus.COMPLETED
        total_tools = len(profile.tools)
        logger.info("Starting scan %s on %s with %d tools", scan_id, target.target_url, total_tools)

        if self._db is not None:
            await self._db.execute(
                "INSERT INTO scans (id, program_id, target_url, target_type, status, started_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, target.program_id, target.target_url,
                 target.target_type.value, ScanStatus.RUNNING.value, started_at.isoformat()),
            )
            await self._db.commit()

        for tool_index, tool in enumerate(profile.tools):
            tool_args = profile.args.get(tool, [])
            tool_timeout = profile.timeout_seconds
            tool_start = time.perf_counter()

            progress_task = asyncio.create_task(
                self._progress_reporter(
                    scan_id=scan_id, tool=tool, tool_index=tool_index,
                    total_tools=total_tools, vulnerabilities_found=len(all_vulnerabilities),
                    tool_start=tool_start, tool_timeout=tool_timeout,
                )
            )

            try:
                raw_output = await self.run_tool(
                    tool=tool, target=target.target_url, args=tool_args, timeout=tool_timeout,
                )
                tools_used.append(tool)
                vulns = self._parse_tool_output(tool, raw_output, scan_id)
                all_vulnerabilities.extend(vulns)

            except ScanTimeoutError:
                logger.warning("Scan %s: tool %s timed out after %.0fs", scan_id, tool.value, tool_timeout)
                tools_used.append(tool)
                final_status = ScanStatus.TIMEOUT
                if self._db is not None:
                    await self._db.execute(
                        "INSERT INTO change_events (program_id, change_type, details, detected_at)"
                        " VALUES (?, ?, ?, ?)",
                        (target.program_id, "scan_timeout",
                         f"Tool {tool.value} timed out after {tool_timeout}s on {target.target_url}",
                         datetime.now(timezone.utc).isoformat()),
                    )
                    await self._db.commit()
                break

            except Exception as e:
                logger.error("Scan %s: tool %s failed: %s", scan_id, tool.value, str(e))
                tools_used.append(tool)
                final_status = ScanStatus.FAILED
                break

            finally:
                progress_task.cancel()
                try:
                    await progress_task
                except asyncio.CancelledError:
                    pass

        # Finalize
        completed_at = datetime.now(timezone.utc)
        duration = (completed_at - started_at).total_seconds()
        result = ScanResult(
            scan_id=scan_id, target=target, status=final_status,
            vulnerabilities=all_vulnerabilities, tools_used=tools_used,
            started_at=started_at, completed_at=completed_at, duration_seconds=duration,
        )

        await self.report_progress(scan_id, ScanProgress(
            scan_id=scan_id, percent_complete=100.0,
            vulnerabilities_found=len(all_vulnerabilities),
            estimated_remaining_seconds=0.0, current_tool=None,
        ))

        if self._db is not None:
            await self._db.execute(
                "UPDATE scans SET status=?, completed_at=?, duration_seconds=? WHERE id=?",
                (final_status.value, completed_at.isoformat(), duration, scan_id),
            )
            await self._db.commit()
            for vuln in all_vulnerabilities:
                await self._db.execute(
                    "INSERT INTO vulnerabilities"
                    " (id, scan_id, cve_id, severity, title, description,"
                    " affected_endpoint, evidence, tool_source, raw_output, discovered_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (vuln.id, scan_id, vuln.cve_id, vuln.severity.value,
                     vuln.title, vuln.description, vuln.affected_endpoint,
                     vuln.evidence, vuln.tool_source.value, vuln.raw_output,
                     vuln.discovered_at.isoformat()),
                )
            await self._db.commit()

        logger.info("Scan %s completed: status=%s, vulns=%d, duration=%.1fs",
                    scan_id, final_status.value, len(all_vulnerabilities), duration)
        return result

    async def _progress_reporter(
        self, scan_id: str, tool: ScanTool, tool_index: int,
        total_tools: int, vulnerabilities_found: int,
        tool_start: float, tool_timeout: float,
    ) -> None:
        """Background task reporting progress every 30 seconds."""
        while True:
            await asyncio.sleep(_PROGRESS_REPORT_INTERVAL)
            elapsed = time.perf_counter() - tool_start
            tool_progress = min(elapsed / tool_timeout, 0.95)
            overall = ((tool_index + tool_progress) / total_tools) * 100.0
            remaining_tool = max(tool_timeout - elapsed, 0.0)
            remaining_total = remaining_tool + (total_tools - tool_index - 1) * tool_timeout
            await self.report_progress(scan_id, ScanProgress(
                scan_id=scan_id, percent_complete=min(overall, 99.0),
                vulnerabilities_found=vulnerabilities_found,
                estimated_remaining_seconds=remaining_total, current_tool=tool,
            ))

    def _parse_tool_output(self, tool: ScanTool, raw_output: str, scan_id: str) -> list[Vulnerability]:
        """Parse raw tool output using the appropriate module-level parser."""
        try:
            if tool == ScanTool.NMAP:
                vulns = parse_nmap_xml(raw_output)
            elif tool == ScanTool.NUCLEI:
                vulns = parse_nuclei_json(raw_output)
            elif tool == ScanTool.NIKTO:
                vulns = parse_nikto_output(raw_output)
            elif tool == ScanTool.SQLMAP:
                vulns = parse_sqlmap_output(raw_output)
            else:
                return []
            for vuln in vulns:
                vuln.scan_id = scan_id
            return vulns
        except Exception as e:
            logger.warning("Failed to parse %s output: %s", tool.value, str(e))
            return []

