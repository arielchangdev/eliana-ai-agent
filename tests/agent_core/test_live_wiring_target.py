"""Tasks 1.3 / 1.4 / 1.5 — target threading verification (eliana-agent-live-wiring).

A stub cannot hide a broken wire: the SpyScanEngine ASSERTS the target it
receives is the authorized target and non-empty, failing loudly on empty/wrong
target — directly guarding the `target=""` regression.

  Property 1: target reaching the engine == gated target and is non-empty
  Property 2: planner cannot influence the target (independent of call.arguments)
"""
import asyncio

import pytest
from hypothesis import given, settings, strategies as st

from agent_core.eliana.mcp_server import ElianaMCPServer, _resolve_scan_tool
from agent_core.guardrail import GuardrailGate
from app.bounty.scanner import ScanEngine
from agent_core.planning_loop import PlanningLoop
from agent_core.models import (
    AssessmentGoal,
    DecisionKind,
    GateContext,
    GateDecision,
    GateOutcome,
    PlannerDecision,
    ToolCall,
)
from app.bounty.models import ProgramScope

AUTH_TARGET = "https://app.example.com"
AUTH_SCOPE = ProgramScope(domains=["app.example.com"])
# The bare host the tool (run_tool) must receive — scheme stripped in _do_recon,
# mirroring legacy scan_host. The gate still checks scope on the scheme'd URL.
AUTH_HOST = "app.example.com"


# --------------------------------------------------------------------------- #
# SpyScanEngine — records target, asserts it is authorized + non-empty
# --------------------------------------------------------------------------- #
class SpyScanEngine:
    """Test double for ScanEngine. run_tool records the target it was called
    with and ASSERTS it is non-empty and equals the authorized target. Fails
    LOUDLY (AssertionError) on an empty or wrong target — so a broken wire can
    never pass silently."""

    def __init__(self, authorized_target: str, raw_output: str = ""):
        self._authorized = authorized_target
        # The tool-facing target is the BARE host (scheme stripped in
        # _do_recon, mirroring legacy scan_host). The gated target_url may carry
        # a scheme (needed for the gate's urlparse scope check); tools must get
        # the bare host. We assert run_tool receives exactly that bare host.
        self._expected_host = authorized_target.split("://")[-1].split("/")[0]
        self._raw_output = raw_output
        self.calls = []  # list of (tool, target, args)
        self._real = ScanEngine()  # delegate real parsing (faithful fake)

    def run_tool(self, tool, target, args, timeout=1800.0):
        self.calls.append((tool, target, list(args)))
        assert target, (
            f"SpyScanEngine.run_tool called with EMPTY target "
            f"(the target='' regression) — tool={getattr(tool,'value',tool)}")
        assert target == self._expected_host, (
            f"SpyScanEngine got target={target!r} but expected the BARE host "
            f"{self._expected_host!r} (scheme must be stripped before run_tool)")
        # a bare host must NOT carry a scheme (tools want IP/host, not a URL)
        assert "://" not in target, (
            f"run_tool received a scheme'd target {target!r} — tools need bare host")
        # default: empty output (these tests only verify the target reaches the
        # engine); a raw_output may be supplied to exercise real parsing too.
        return self._raw_output

    def _parse_tool_output(self, tool, raw_output, scan_id="", target=""):
        # reuse the REAL dispatcher the agent path delegates to (no reinvention)
        return self._real._parse_tool_output(tool, raw_output, scan_id, target)


def _authorizer_ok():
    class _A:
        def is_authorized(self, target_url):
            return True
    return _A()


def _allow_nmap(token="tok-1"):
    """A GateDecision an already-gated ALLOW would produce for nmap."""
    return GateDecision(outcome=GateOutcome.ALLOW,
                        call=ToolCall("nmap", {}), token=token)


# --------------------------------------------------------------------------- #
# Task 1.3 — unit tests: ctx threads target to the spy; ctx=None short-circuits
# --------------------------------------------------------------------------- #
def test_invoke_with_ctx_reaches_engine_with_authorized_target():
    spy = SpyScanEngine(AUTH_TARGET)
    srv = ElianaMCPServer(scan_engine=spy, attack_mapper=lambda *a, **k: None)
    call = ToolCall("nmap", {})
    ctx = GateContext(target_url=AUTH_TARGET, scope=AUTH_SCOPE,
                      authorizer=_authorizer_ok())
    asyncio.run(srv.invoke(call, _allow_nmap(), ctx))
    # spy was called exactly once, with the authorized target as a BARE host
    # (scheme stripped before run_tool; the gated ctx carries the scheme'd URL)
    assert len(spy.calls) == 1
    tool, target, args = spy.calls[0]
    assert target == AUTH_HOST
    assert "://" not in target and target != ""


def test_invoke_ctx_none_short_circuits_and_does_not_call_engine():
    spy = SpyScanEngine(AUTH_TARGET)
    srv = ElianaMCPServer(scan_engine=spy, attack_mapper=lambda *a, **k: None)
    call = ToolCall("nmap", {})
    obs = asyncio.run(srv.invoke(call, _allow_nmap(), None))   # no ctx
    # honest-empty: zero findings, and the spy was NEVER called with "" target
    assert obs.findings == []
    assert spy.calls == [], "engine must not be called when target is unavailable"


def test_do_recon_empty_target_short_circuits():
    spy = SpyScanEngine(AUTH_TARGET)
    srv = ElianaMCPServer(scan_engine=spy, attack_mapper=lambda *a, **k: None)
    obs = asyncio.run(srv._do_recon(ToolCall("nmap", {}), ""))
    assert obs.findings == []
    assert spy.calls == []


def test_do_recon_whitespace_target_short_circuits():
    spy = SpyScanEngine(AUTH_TARGET)
    srv = ElianaMCPServer(scan_engine=spy, attack_mapper=lambda *a, **k: None)
    obs = asyncio.run(srv._do_recon(ToolCall("nmap", {}), "   "))
    assert obs.findings == []
    assert spy.calls == []


def test_non_scan_tools_ignore_ctx_and_behave_unchanged():
    """classify/recall/record must not touch the scan engine regardless of ctx."""
    spy = SpyScanEngine(AUTH_TARGET)

    class _Mem:
        def recall_focus_hints(self, tt, query="", k=3):
            return ["hint"]
    srv = ElianaMCPServer(scan_engine=spy, attack_mapper=lambda *a, **k: None,
                          memory=_Mem())
    ctx = GateContext(target_url=AUTH_TARGET, scope=AUTH_SCOPE,
                      authorizer=_authorizer_ok())
    call = ToolCall("recall_experience", {"target_type": "web_app"})
    appr = GateDecision(GateOutcome.ALLOW, call, token="tok-r")
    asyncio.run(srv.invoke(call, appr, ctx))
    assert spy.calls == []   # scan engine untouched by a non-scan tool


# --------------------------------------------------------------------------- #
# Task 1.4 — end-to-end loop test: real goal -> planner -> gate -> invoke -> spy
# --------------------------------------------------------------------------- #
class _ScriptedPlanner:
    def __init__(self, decisions):
        self._d = list(decisions)
    async def decide(self, state):
        if self._d:
            return self._d.pop(0)
        return PlannerDecision(kind=DecisionKind.STOP, rationale="done")


def test_e2e_loop_engine_sees_goal_target():
    """Drive a real AssessmentGoal through planner -> GuardrailGate -> invoke
    into SpyScanEngine; assert the spy saw the goal's target_url. Directly
    reproduces & guards the target='' regression."""
    spy = SpyScanEngine(AUTH_TARGET)
    srv = ElianaMCPServer(scan_engine=spy, attack_mapper=lambda *a, **k: None)
    gate = GuardrailGate()
    planner = _ScriptedPlanner([
        PlannerDecision(kind=DecisionKind.INVOKE_TOOL,
                        tool_call=ToolCall("nmap", {}), rationale="recon"),
        PlannerDecision(kind=DecisionKind.STOP, rationale="done"),
    ])
    goal = AssessmentGoal(target_url=AUTH_TARGET, scope=AUTH_SCOPE,
                          description="assess web_app", max_steps=5)

    # NOTE: loop forwarding of ctx into invoke is task 6.1. For this wave we
    # verify the invoke+engine wiring directly carries the gated target, which
    # is the regression-critical seam. We assert via the gate-built ctx.
    ctx = GateContext(target_url=goal.target_url, scope=goal.scope,
                      authorizer=_authorizer_ok())
    decision = asyncio.run(planner.decide(None))
    gd = gate.check(decision.tool_call, ctx)
    assert gd.outcome == GateOutcome.ALLOW
    asyncio.run(srv.invoke(gd.call, gd, ctx))

    assert len(spy.calls) == 1
    _, target, _ = spy.calls[0]
    # engine sees the goal's host as a BARE host (scheme stripped for the tool)
    assert target == AUTH_HOST and "://" not in target and target != ""


# --------------------------------------------------------------------------- #
# Task 1.5 — property: planner cannot influence the target
# --------------------------------------------------------------------------- #
# adversarial call.arguments: injected hosts / urls the planner might smuggle
_adversarial_args = st.fixed_dictionaries({}).flatmap(lambda _: st.dictionaries(
    keys=st.sampled_from(["host", "target", "url", "args", "server"]),
    values=st.sampled_from([
        "evil.com", "http://attacker.example", "127.0.0.1", "10.0.0.1",
        "--host=evil.com", "169.254.169.254", "internal.corp"]),
    max_size=4))


@settings(max_examples=150, deadline=None)
@given(adv_args=_adversarial_args, token=st.integers(min_value=1, max_value=10**6))
def test_p2_planner_cannot_influence_target(adv_args, token):
    """For any adversarial call.arguments, the target the engine receives comes
    solely from ctx (the gated goal), never from call.arguments."""
    spy = SpyScanEngine(AUTH_TARGET)
    srv = ElianaMCPServer(scan_engine=spy, attack_mapper=lambda *a, **k: None)
    # planner-proposed call carries adversarial arguments
    call = ToolCall("nmap", dict(adv_args))
    appr = GateDecision(GateOutcome.ALLOW, call, token=f"tok-{token}")
    ctx = GateContext(target_url=AUTH_TARGET, scope=AUTH_SCOPE,
                      authorizer=_authorizer_ok())
    asyncio.run(srv.invoke(call, appr, ctx))
    # spy's own assertions already enforce target==AUTH_HOST & non-empty;
    # double-check here that no adversarial value leaked into the target
    assert len(spy.calls) == 1
    _, target, _ = spy.calls[0]
    assert target == AUTH_HOST
    for v in adv_args.values():
        assert target != v, f"adversarial arg {v!r} leaked into target"


# --------------------------------------------------------------------------- #
# Regression — bare-IP target: scope normalization so the gate ALLOWs a bare IP
# (root cause of the live agent run DENY: urlparse(bare IP).hostname == None ->
# is_target_in_scope False -> gate DENY every step). Fix (option A): the agent
# path threads a scheme'd target_url into GateContext so the gate's scope check
# passes, and _do_recon strips the scheme back to a bare host before run_tool.
# We do NOT touch GuardrailGate.check or is_target_in_scope.
# --------------------------------------------------------------------------- #
import importlib.util
import os as _os

BARE_IP = "198.51.100.32"
IP_SCOPE = ProgramScope(domains=[BARE_IP])


def _load_normalizer():
    """Load _normalize_scope_target from the hyphenated eliana-integration pkg."""
    repo_root = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), "..", ".."))
    path = _os.path.join(repo_root, "eliana-integration", "telegram_runtime.py")
    spec = importlib.util.spec_from_file_location("telegram_runtime_norm", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod._normalize_scope_target


def test_normalizer_adds_scheme_to_bare_ip_only():
    norm = _load_normalizer()
    assert norm("198.51.100.32") == "https://198.51.100.32"   # bare IP -> scheme'd
    assert norm("app.example.com") == "https://app.example.com"
    # already-scheme'd is left unchanged (no double prefix)
    assert norm("https://198.51.100.32") == "https://198.51.100.32"
    assert norm("http://x.example") == "http://x.example"
    assert norm("") == ""


def test_bare_ip_goal_gate_allows_after_normalization():
    """The exact live-run failure: a bare-IP target. With the agent path's
    normalization, GateContext.target_url carries a scheme so the REAL
    GuardrailGate ALLOWs (previously DENYed 'target not in scope')."""
    norm = _load_normalizer()
    gate = GuardrailGate()
    # agent path builds scope from the bare host, target_url from the normalized
    ctx = GateContext(target_url=norm(BARE_IP), scope=IP_SCOPE,
                      authorizer=_authorizer_ok())
    gd = gate.check(ToolCall("nmap", {}), ctx)
    assert gd.outcome == GateOutcome.ALLOW, (
        f"bare-IP target still DENYed after normalization: {gd.reason!r}")
    assert gd.token


def test_bare_ip_run_tool_receives_bare_host_not_url():
    """After ALLOW, _do_recon must hand run_tool the BARE IP (scheme stripped) —
    nmap et al. need a host/IP, not a URL."""
    norm = _load_normalizer()
    spy = SpyScanEngine(norm(BARE_IP))   # expects bare host 198.51.100.32
    srv = ElianaMCPServer(scan_engine=spy)
    gate = GuardrailGate()
    ctx = GateContext(target_url=norm(BARE_IP), scope=IP_SCOPE,
                      authorizer=_authorizer_ok())
    gd = gate.check(ToolCall("nmap", {}), ctx)
    assert gd.outcome == GateOutcome.ALLOW
    asyncio.run(srv.invoke(gd.call, gd, ctx))
    assert len(spy.calls) == 1
    _, target, _ = spy.calls[0]
    assert target == BARE_IP                 # bare IP, no scheme
    assert "://" not in target
