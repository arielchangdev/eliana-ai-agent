"""Task 8 — final end-to-end integration (eliana-agent-live-wiring).

Drives a real AssessmentGoal through the WHOLE wired chain with real components
(GuardrailGate, ElianaMCPServer, PlanningLoop, AgentRunPersister) and a spy
ScanEngine returning REAL captured fixtures. Proves the three end-to-end
properties the defect violated, in one flow:

  Property 1 — the engine saw the AUTHORIZED, non-empty target (not target="")
  Property 3 — real findings with ATT&CK labels were surfaced (not a fake
               {"severity":"info"} placeholder)
  Property 6 — a scans row + one vulnerabilities row per finding were written to
               bounty.db (so "0 findings, no trace" is un-reproducible)

Only the external edges are stubbed: a spy engine (no real Kali/host), a fixed
scripted planner (no Ollama), and a TEMP-FILE bounty.db (never the production
db). No real scan is performed.
"""
import asyncio
import os
import tempfile

import aiosqlite

from agent_core.eliana.mcp_server import ElianaMCPServer
from agent_core.guardrail import GuardrailGate
from agent_core.planning_loop import PlanningLoop
from agent_core.models import (
    AssessmentGoal, DecisionKind, GateOutcome, PlannerDecision, ToolCall,
)

from app.bounty.scanner import ScanEngine
from app.bounty.enums import ScanTool
from app.bounty.database import init_bounty_db
from app.bounty.agent_run_persister import AgentRunPersister, AGENT_ORIGIN_MARKER
from app.bounty.models import ProgramScope

import tests.agent_core.tool_output_fixtures as fx

AUTH_TARGET = "https://app.example.com"
AUTH_HOST = "app.example.com"
AUTH_SCOPE = ProgramScope(domains=["app.example.com"])


class SpyFixtureEngine:
    """Spy ScanEngine: records every target it was dispatched with (and asserts
    none is empty), returns the REAL fixture for the tool, and delegates parsing
    to the real ScanEngine (no reinvention)."""
    def __init__(self):
        self._real = ScanEngine()
        self.seen = []  # (tool, target)
    def run_tool(self, tool, target, args, timeout=1800.0):
        assert target, "engine dispatched with EMPTY target (target='' regression)"
        self.seen.append((getattr(tool, "value", tool), target))
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
                                   tool_call=ToolCall(t, {"host": "evil.example"}),
                                   rationale=f"recon {t}") for t in tools]
        self._d.append(PlannerDecision(kind=DecisionKind.STOP, rationale="done"))
    async def decide(self, state):
        return self._d.pop(0) if self._d else PlannerDecision(
            kind=DecisionKind.STOP, rationale="done")


def _make_temp_db_path():
    fd, path = tempfile.mkstemp(suffix=".db", prefix="eliana_e2e_")
    os.close(fd)
    os.unlink(path)
    return path


def _safe_unlink(path):
    for p in (path, path + "-wal", path + "-shm"):
        try:
            os.unlink(p)
        except OSError:
            pass


def test_final_e2e_goal_to_persist_makes_no_trace_unreproducible():
    async def _run():
        db_path = _make_temp_db_path()
        try:
            conn = await init_bounty_db(db_path)
            await conn.close()

            engine = SpyFixtureEngine()
            srv = ElianaMCPServer(scan_engine=engine)
            gate = GuardrailGate()
            # nmap (2 INFO, T1046) + sslscan (1 MEDIUM, T1600 -> a report)
            planner = _ScriptedPlanner([ScanTool.NMAP.value, ScanTool.SSLSCAN.value])
            loop = PlanningLoop(planner=planner, gate=gate, tools=srv,
                                authorizer=_Authz(), memory=None, max_steps=10)
            goal = AssessmentGoal(target_url=AUTH_TARGET, scope=AUTH_SCOPE,
                                  description="assess web_app", max_steps=10)

            outcome = await loop.run(goal)

            # ---- Property 1: engine saw the AUTHORIZED, non-empty target ---- #
            assert engine.seen, "engine was never dispatched"
            for tool_value, target in engine.seen:
                assert target, "empty target reached the engine"
                # the target is the gated goal host, NOT the planner's injected
                # adversarial 'host' argument
                assert "evil.example" not in target
            assert [t for t, _ in engine.seen] == ["nmap", "sslscan"]

            # ---- Property 3: real findings with ATT&CK labels surfaced ------ #
            assert len(outcome.findings) == 3, outcome.findings
            sevs = sorted(f["severity"] for f in outcome.findings)
            assert sevs == ["info", "info", "medium"], sevs
            techniques = {f.get("attack_technique_id") for f in outcome.findings}
            assert "T1046" in techniques            # nmap open-port
            assert "T1600" in techniques            # sslscan deprecated TLS
            for f in outcome.findings:
                assert f.get("attack_technique_id"), f
                # projection honesty: no raw payload leaks to the planner surface
                assert "raw_output" not in f and "evidence" not in f

            # the gate still gated every step (ALLOW with a one-time token)
            allow_steps = [s for s in outcome.trace.steps
                           if s.gate.outcome == GateOutcome.ALLOW]
            assert len(allow_steps) == 2
            assert all(s.gate.token for s in allow_steps)

            # ---- Property 6: persisted to bounty.db (scans + vulns rows) ---- #
            persister = AgentRunPersister(db_path=db_path, report_llm=None)
            scan_id = await persister.persist(outcome)

            async with aiosqlite.connect(db_path) as c:
                scans = await (await c.execute(
                    "SELECT id, target_url, status, profile FROM scans")).fetchall()
                vulns = await (await c.execute(
                    "SELECT severity, affected_endpoint, attack_technique_id,"
                    " scan_id FROM vulnerabilities")).fetchall()
                reports = await (await c.execute(
                    "SELECT vulnerability_id FROM reports")).fetchall()

            # exactly one scans row for the authorized host, tagged agent origin
            assert len(scans) == 1
            sid, turl, status, profile = scans[0]
            assert sid == scan_id
            assert turl == AUTH_HOST
            assert status == "completed"
            assert AGENT_ORIGIN_MARKER["origin"] in (profile or "")

            # one vulnerabilities row per surfaced finding, all tied to this scan
            assert len(vulns) == len(outcome.findings)
            for severity, endpoint, tech_id, v_scan_id in vulns:
                assert v_scan_id == scan_id
                assert endpoint, "empty endpoint persisted"
                assert tech_id, "ATT&CK id not persisted"

            # the MEDIUM finding produced a report -> "no trace" is dead
            assert len(reports) >= 1, "MEDIUM+ finding produced no report row"
        finally:
            _safe_unlink(db_path)

    asyncio.run(_run())
