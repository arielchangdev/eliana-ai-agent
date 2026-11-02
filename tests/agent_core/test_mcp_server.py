"""Task 5.3 — unit tests for ElianaMCPServer.invoke token handling + list_tools.

This is Property 1 (no-bypass) enforced a SECOND time at the MCP layer (defense
in depth): the server re-asserts the gate verdict and refuses any invoke lacking
a valid ALLOW token issued for the exact call.

  - missing / mismatched / reused token => ToolNotApproved, nothing runs, audited
  - only a valid ALLOW (token issued for this exact call) dispatches
  - list_tools() never exposes sqlmap or any exploitation tool
"""
import asyncio

import pytest

from agent_core.eliana.mcp_server import ElianaMCPServer, ToolNotApproved
from agent_core.models import (
    GateContext, GateDecision, GateOutcome, Observation, ToolCall,
)
from app.bounty.models import ProgramScope

# Scan dispatch now requires a ctx carrying the gated target (live-wiring fix:
# invoke(call, approval, ctx)). Tests that expect the engine to run pass this.
_AUTH_TARGET = "https://app.example.com"


def _ctx():
    class _A:
        def is_authorized(self, target_url):
            return True
    return GateContext(target_url=_AUTH_TARGET,
                       scope=ProgramScope(domains=["app.example.com"]),
                       authorizer=_A())


from app.bounty.scanner import ScanEngine
import tests.agent_core.tool_output_fixtures as fx


class StubEngine:
    """Records whether run_tool was dispatched, and with what args.

    run_tool returns a REAL nmap-XML fixture (two open ports) so the rewritten
    _parse_recon_output exercises the real legacy parser pipeline and produces a
    real finding — a faithful fake, not a reinvented parser. _parse_tool_output
    delegates to the real ScanEngine (the dispatcher the agent path reuses)."""
    def __init__(self):
        self.calls = []
        self._real = ScanEngine()
        self._fixture = fx.load_fixture(fx.ScanTool.NMAP, "finding")
    def run_tool(self, tool, target, args, timeout=1800.0):
        self.calls.append((tool, target, list(args)))
        return self._fixture
    def _parse_tool_output(self, tool, raw_output, scan_id="", target=""):
        return self._real._parse_tool_output(tool, raw_output, scan_id, target)


def _server():
    audit = []
    # No attack_mapper injection: the rewritten _parse_recon_output calls the
    # module-level map_finding_to_attack directly (same as legacy execute_scan).
    srv = ElianaMCPServer(scan_engine=StubEngine(), audit_sink=audit.append)
    return srv, audit


def _allow(call: ToolCall, token: str = "tok-1") -> GateDecision:
    return GateDecision(outcome=GateOutcome.ALLOW, call=call, token=token)


# --- valid ALLOW dispatches ------------------------------------------------- #
def test_valid_allow_dispatches_and_returns_observation():
    srv, audit = _server()
    call = ToolCall("nmap", {})
    obs = asyncio.run(srv.invoke(call, _allow(call), _ctx()))
    assert isinstance(obs, Observation)
    assert obs.tool_name == "nmap"
    # dispatched to the real engine exactly once, with the authorized target
    assert len(srv._scan_engine.calls) == 1
    assert srv._scan_engine.calls[0][1] == _AUTH_TARGET
    # finding carries severity + ATT&CK label only; no raw payload field
    f = obs.findings[0]
    assert f["severity"] == "info"
    assert f["attack_technique_id"] == "T1046"
    assert "payload" not in f and "raw_output" not in f
    assert any(r["event"] == "dispatched" for r in audit)


# --- missing token ---------------------------------------------------------- #
def test_missing_token_refused():
    srv, audit = _server()
    call = ToolCall("nmap", {})
    appr = GateDecision(outcome=GateOutcome.ALLOW, call=call, token="")
    with pytest.raises(ToolNotApproved):
        asyncio.run(srv.invoke(call, appr))
    assert len(srv._scan_engine.calls) == 0  # nothing ran
    assert any(r["event"] == "rejected" for r in audit)


# --- DENY approval refused -------------------------------------------------- #
def test_deny_approval_refused():
    srv, audit = _server()
    call = ToolCall("nmap", {})
    appr = GateDecision(outcome=GateOutcome.DENY, call=call, token="tok-x",
                        reason="denied")
    with pytest.raises(ToolNotApproved):
        asyncio.run(srv.invoke(call, appr))
    assert len(srv._scan_engine.calls) == 0
    assert any(r["event"] == "rejected" for r in audit)


# --- mismatched call (approval issued for a different call) ----------------- #
def test_mismatched_token_refused():
    srv, audit = _server()
    call = ToolCall("nmap", {})
    other = ToolCall("nikto", {})
    # approval was issued for `other`, but we try to invoke `call`
    appr = GateDecision(outcome=GateOutcome.ALLOW, call=other, token="tok-2")
    with pytest.raises(ToolNotApproved):
        asyncio.run(srv.invoke(call, appr))
    assert len(srv._scan_engine.calls) == 0
    assert any(r["event"] == "rejected" for r in audit)


# --- reused token ----------------------------------------------------------- #
def test_reused_token_refused():
    srv, _ = _server()
    call = ToolCall("nmap", {})
    appr = _allow(call, token="tok-3")
    # first invoke dispatches (ctx carries the gated target)
    asyncio.run(srv.invoke(call, appr, _ctx()))
    assert len(srv._scan_engine.calls) == 1
    # second invoke with the SAME token must be refused; no second dispatch
    with pytest.raises(ToolNotApproved):
        asyncio.run(srv.invoke(call, appr, _ctx()))
    assert len(srv._scan_engine.calls) == 1


def test_token_consumed_even_across_distinct_decisions():
    """A token value, once consumed, cannot be reused even wrapped in a fresh
    GateDecision object for the same call."""
    srv, _ = _server()
    call = ToolCall("nmap", {})
    asyncio.run(srv.invoke(call, _allow(call, token="dup"), _ctx()))
    with pytest.raises(ToolNotApproved):
        asyncio.run(srv.invoke(call, _allow(call, token="dup"), _ctx()))
    assert len(srv._scan_engine.calls) == 1


# --- list_tools never exposes sqlmap / exploitation ------------------------- #
def test_list_tools_excludes_sqlmap_and_exploitation():
    srv, _ = _server()
    specs = srv.list_tools()
    names = {s.name for s in specs}
    assert names == {"recon_scan", "classify_attack", "recall_experience",
                     "record_experience"}
    recon = next(s for s in specs if s.name == "recon_scan")
    enum = recon.input_schema["properties"]["tool"]["enum"]
    assert "sqlmap" not in enum
    assert not any(bad in enum for bad in ("metasploit", "msfconsole", "exploit"))
    # schema deliberately exposes no args field (planner never picks flags)
    assert "args" not in recon.input_schema["properties"]


def test_recon_enum_equals_auto_orchestration_allowlist():
    from app.bounty.scanner import _AUTO_ORCHESTRATION_TOOLS
    srv, _ = _server()
    recon = next(s for s in srv.list_tools() if s.name == "recon_scan")
    enum = set(recon.input_schema["properties"]["tool"]["enum"])
    assert enum == {t.value for t in _AUTO_ORCHESTRATION_TOOLS}
