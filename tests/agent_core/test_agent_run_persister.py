"""Task 5.2 — AgentRunPersister persistence round-trip (eliana-agent-live-wiring).

Makes "0 findings, no trace in bounty.db" un-reproducible: persist a real
agent run (spy engine returning real tool fixtures) and assert bounty.db has
exactly one scans row for the target + one vulnerabilities row per finding
(with severities + ATT&CK labels), that MEDIUM+ findings produced reports, and
that the agent-origin marker is present in the pre-existing `profile` column
(no schema migration).

  Property 6: persistence round-trip

All fake/spy + a TEMP-FILE bounty.db — no real Ollama/Kali/scan, never touches
the production db.
"""
import asyncio
import os
import tempfile

import aiosqlite
import pytest

from agent_core.eliana.mcp_server import ElianaMCPServer
from agent_core.guardrail import GuardrailGate
from agent_core.planning_loop import PlanningLoop
from agent_core.models import (
    AssessmentGoal, DecisionKind, PlannerDecision, ToolCall,
)

from app.bounty.scanner import ScanEngine
from app.bounty.enums import ScanTool
from app.bounty.database import init_bounty_db
from app.bounty.agent_run_persister import AgentRunPersister, AGENT_ORIGIN_MARKER

import tests.agent_core.tool_output_fixtures as fx
from app.bounty.models import ProgramScope

AUTH_TARGET = "https://app.example.com"
AUTH_HOST = "app.example.com"
AUTH_SCOPE = ProgramScope(domains=["app.example.com"])


# --------------------------------------------------------------------------- #
# Fixture-returning spy engine (faithful: delegates real parsing)
# --------------------------------------------------------------------------- #
class FixtureEngine:
    """ScanEngine double: run_tool returns the real captured fixture for the
    tool; _parse_tool_output delegates to the real ScanEngine (no reinvention).
    Records the targets it saw so we can assert the authorized target reached
    the engine (never ``""``)."""
    def __init__(self):
        self._real = ScanEngine()
        self.targets = []
    def run_tool(self, tool, target, args, timeout=1800.0):
        self.targets.append(target)
        return fx.load_fixture(tool, "finding")
    def _parse_tool_output(self, tool, raw_output, scan_id="", target=""):
        return self._real._parse_tool_output(tool, raw_output, scan_id, target)


class _Authz:
    def is_authorized(self, target_url):
        return True
    def focus_hints(self, goal):
        return []
    def priority_tools(self, goal):
        return []


class _ScriptedPlanner:
    def __init__(self, tools):
        self._d = [PlannerDecision(kind=DecisionKind.INVOKE_TOOL,
                                   tool_call=ToolCall(t, {}),
                                   rationale=f"recon {t}") for t in tools]
        self._d.append(PlannerDecision(kind=DecisionKind.STOP, rationale="done"))
    async def decide(self, state):
        return self._d.pop(0) if self._d else PlannerDecision(
            kind=DecisionKind.STOP, rationale="done")


def _make_temp_db_path():
    fd, path = tempfile.mkstemp(suffix=".db", prefix="eliana_agent_test_")
    os.close(fd)
    os.unlink(path)  # let init_bounty_db create it fresh
    return path


async def _init_schema(path):
    conn = await init_bounty_db(path)
    await conn.close()


async def _build_outcome(engine, tools):
    """Drive a real wired loop (planner -> gate -> invoke(+ctx) -> engine ->
    real parse) and return the AssessmentOutcome. Exercises the Task 6.1 ctx
    forwarding so findings are REAL (not honest-empty)."""
    srv = ElianaMCPServer(scan_engine=engine)
    gate = GuardrailGate()
    planner = _ScriptedPlanner(tools)
    loop = PlanningLoop(planner=planner, gate=gate, tools=srv,
                        authorizer=_Authz(), memory=None, max_steps=10)
    goal = AssessmentGoal(target_url=AUTH_TARGET, scope=AUTH_SCOPE,
                          description="assess web_app", max_steps=10)
    return await loop.run(goal)


def _safe_unlink(path):
    for p in (path, path + "-wal", path + "-shm"):
        try:
            os.unlink(p)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Property 6 — persistence round-trip
# --------------------------------------------------------------------------- #
def test_persist_writes_scans_and_vulns_rows_and_reports():
    async def _run():
        db_path = _make_temp_db_path()
        try:
            await _init_schema(db_path)
            engine = FixtureEngine()
            # nmap (2 INFO, T1046) then sslscan (1 MEDIUM, T1600 -> report).
            outcome = await _build_outcome(
                engine, [ScanTool.NMAP.value, ScanTool.SSLSCAN.value])

            # the authorized, non-empty target reached the engine
            assert engine.targets, "engine was never called"
            assert all(t for t in engine.targets), "empty target reached engine"
            assert all(t in (AUTH_HOST, AUTH_TARGET) for t in engine.targets), \
                engine.targets
            # real findings surfaced (not honest-empty) now that ctx is forwarded
            assert outcome.findings, "loop produced no findings after ctx wiring"

            persister = AgentRunPersister(db_path=db_path, report_llm=None)
            scan_id = await persister.persist(outcome)
            assert scan_id

            async with aiosqlite.connect(db_path) as conn:
                cur = await conn.execute(
                    "SELECT id, program_id, target_url, status, profile FROM scans")
                scans = await cur.fetchall()
                cur = await conn.execute(
                    "SELECT severity, affected_endpoint, tool_source,"
                    " attack_technique_id, scan_id FROM vulnerabilities")
                vulns = await cur.fetchall()
                cur = await conn.execute(
                    "SELECT vulnerability_id, attack_technique_id FROM reports")
                reports = await cur.fetchall()

            # exactly one scans row, tagged agent origin via the profile column
            assert len(scans) == 1, scans
            sid, prog, turl, status, profile = scans[0]
            assert sid == scan_id
            assert prog == "manual"
            assert turl == AUTH_HOST
            assert status == "completed"
            assert AGENT_ORIGIN_MARKER["origin"] in (profile or "")

            # one vulnerabilities row per surfaced finding, all tied to this scan
            assert len(vulns) == len(outcome.findings), \
                (len(vulns), len(outcome.findings))
            for severity, endpoint, tool_source, tech_id, v_scan_id in vulns:
                assert v_scan_id == scan_id
                assert severity in {"info", "low", "medium", "high", "critical"}
                assert endpoint, "empty endpoint persisted"
                assert tech_id, "ATT&CK technique id not persisted"

            # MEDIUM+ -> at least one report with a valid FK
            med_plus = [v for v in vulns if v[0] in {"medium", "high", "critical"}]
            assert med_plus, "expected a MEDIUM+ finding from the sslscan fixture"
            assert len(reports) >= 1, "MEDIUM+ finding produced no report"
            for vuln_id, _rep_tech in reports:
                assert vuln_id, "report missing vulnerability_id FK"
        finally:
            _safe_unlink(db_path)

    asyncio.run(_run())


def test_persist_scans_row_is_single_even_with_many_findings():
    async def _run():
        db_path = _make_temp_db_path()
        try:
            await _init_schema(db_path)
            engine = FixtureEngine()
            outcome = await _build_outcome(engine, [ScanTool.GOBUSTER.value])  # 4 INFO
            persister = AgentRunPersister(db_path=db_path, report_llm=None)
            await persister.persist(outcome)
            async with aiosqlite.connect(db_path) as conn:
                n_scans = (await (await conn.execute(
                    "SELECT COUNT(*) FROM scans")).fetchone())[0]
                n_vulns = (await (await conn.execute(
                    "SELECT COUNT(*) FROM vulnerabilities")).fetchone())[0]
            assert n_scans == 1
            assert n_vulns == len(outcome.findings) >= 1
        finally:
            _safe_unlink(db_path)

    asyncio.run(_run())


def test_persist_db_failure_raises_not_silent():
    """A db failure must be LOUD (raise), never a silent drop/fabrication."""
    async def _run():
        bad_path = os.path.join(tempfile.gettempdir(),
                                "no_such_dir_eliana_xyz", "nope", "bounty.db")
        persister = AgentRunPersister(db_path=bad_path, report_llm=None)

        class _Trace:
            goal = AssessmentGoal(target_url=AUTH_TARGET, scope=AUTH_SCOPE,
                                  max_steps=1)
        class _Outcome:
            trace = _Trace()
            findings = [{"severity": "info", "title": "x",
                         "affected_endpoint": "h:1/tcp", "tool": "nmap",
                         "attack_technique_id": "T1046"}]
        with pytest.raises(Exception):
            await persister.persist(_Outcome())

    asyncio.run(_run())
