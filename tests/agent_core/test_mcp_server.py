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
from agent_core.models import GateDecision, GateOutcome, Observation, ToolCall


class StubEngine:
    """Records whether run_tool was dispatched, and with what args."""
    def __init__(self):
        self.calls = []
    def run_tool(self, tool, target, args, timeout=1800.0):
        self.calls.append((tool, target, list(args)))
        return "stub tool output: open 80/tcp"


def _mapper(tool, title="", description=""):
    class _T:
        technique_id = "T1046"
        technique_name = "Network Service Discovery"
        tactic_id = "TA0007"
        tactic_name = "Discovery"
    return _T()


def _server():
    audit = []
    srv = ElianaMCPServer(scan_engine=StubEngine(), attack_mapper=_mapper,
                          audit_sink=audit.append)
    return srv, audit


def _allow(call: ToolCall, token: str = "tok-1") -> GateDecision:
    return GateDecision(outcome=GateOutcome.ALLOW, call=call, token=token)


# --- valid ALLOW dispatches ------------------------------------------------- #
def test_valid_allow_dispatches_and_returns_observation():
    srv, audit = _server()
    call = ToolCall("nmap", {})
    obs = asyncio.run(srv.invoke(call, _allow(call)))
    assert isinstance(obs, Observation)
    assert obs.tool_name == "nmap"
    # dispatched to the real engine exactly once
    assert len(srv._scan_engine.calls) == 1
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
    # first invoke dispatches
    asyncio.run(srv.invoke(call, appr))
    assert len(srv._scan_engine.calls) == 1
    # second invoke with the SAME token must be refused; no second dispatch
    with pytest.raises(ToolNotApproved):
        asyncio.run(srv.invoke(call, appr))
    assert len(srv._scan_engine.calls) == 1


def test_token_consumed_even_across_distinct_decisions():
    """A token value, once consumed, cannot be reused even wrapped in a fresh
    GateDecision object for the same call."""
    srv, _ = _server()
    call = ToolCall("nmap", {})
    asyncio.run(srv.invoke(call, _allow(call, token="dup")))
    with pytest.raises(ToolNotApproved):
        asyncio.run(srv.invoke(call, _allow(call, token="dup")))
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
