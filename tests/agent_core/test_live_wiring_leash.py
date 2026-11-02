"""Task 7 — leash preserved after wiring (eliana-agent-live-wiring).

**Property 7: Leash preserved.** Threading the authorized target changed only
*which host an already-ALLOWed call scans* (invoke / _do_recon / _parse_recon_
output / the loop call-site). It did NOT touch GuardrailGate. These property
tests prove the gate's ALLOW/DENY verdict is EXACTLY the same after wiring as
before — the set of ALLOW-able calls did not grow.

The "before wiring" verdict is encoded by an independent reference oracle
(_leash_oracle) built directly from the pre-agent leash rules:
  * tool must be in _AUTO_ORCHESTRATION_TOOLS (sqlmap / unknown -> DENY)
  * target must be in scope (out-of-scope -> DENY)
  * target must be authorized (unauthorized -> DENY)
  * otherwise ALLOW, with arguments FORCED to _EVAL_MODE_ARGS[tool]

Core assertion (韁繩沒鬆 / the leash did not loosen): for every generated
(call, ctx), the live GuardrailGate ALLOWs IFF the oracle ALLOWs — so wiring the
target turned NO previously-DENYed call into an ALLOW, and turned no ALLOW into a
DENY either. Plus: eval-mode args stay forced, and the one-time token is still
consumed exactly once at the server (defense in depth, unchanged).

  _Requirements: 9.7, 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7_

All fake/spy — no real Ollama/Kali/scan/db.
"""
import asyncio

from hypothesis import given, settings, strategies as st

from app.bounty.models import ProgramScope
from app.bounty.scanner import (
    _AUTO_ORCHESTRATION_TOOLS,
    _EVAL_MODE_ARGS,
    is_target_in_scope,
)
from app.bounty.enums import ScanTool

from agent_core.guardrail import GuardrailGate, _resolve_scan_tool
from agent_core.eliana.mcp_server import ElianaMCPServer, ToolNotApproved
from agent_core.models import GateContext, GateDecision, GateOutcome, ToolCall


# --------------------------------------------------------------------------- #
# strategies (mirror the existing guardrail property tests so the leash is
# tested over the SAME input space — incl. sqlmap, unknown tools, case/space
# variants, adversarial args, in/out-of-scope urls, authorized/unauthorized)
# --------------------------------------------------------------------------- #
_ALL_TOOL_NAMES = [t.value for t in ScanTool]              # includes sqlmap
_EXTRA_NAMES = ["metasploit", "msfconsole", "NMAP", "SqlMap", "nmap ", "exploit"]
tool_names = st.sampled_from(_ALL_TOOL_NAMES + _EXTRA_NAMES)

proposed_args = st.dictionaries(
    keys=st.sampled_from(["args", "flags", "extra", "script", "target", "host"]),
    values=st.lists(st.sampled_from(
        ["--dump", "--script=exploit", "-sV", "--intrusive", "safe",
         "evil.com", "169.254.169.254"]),
        max_size=3),
    max_size=3,
)

hostnames = st.sampled_from([
    "app.example.com", "sub.app.example.com", "evil.com", "example.org",
])
schemes = st.sampled_from(["https://", "http://"])
paths = st.sampled_from(["", "/", "/admin", "/api/v1"])


def _scope() -> ProgramScope:
    return ProgramScope(domains=["app.example.com"])


class _Auth:
    def __init__(self, ok: bool):
        self._ok = ok
    def is_authorized(self, target_url: str) -> bool:
        return self._ok


def _tool_calls():
    return st.builds(ToolCall, tool_name=tool_names, arguments=proposed_args)


def _urls():
    return st.builds(lambda s, h, p: f"{s}{h}{p}", schemes, hostnames, paths)


# --------------------------------------------------------------------------- #
# reference oracle = the pre-wiring leash (what the gate verdict MUST still be)
# --------------------------------------------------------------------------- #
def _leash_oracle(call: ToolCall, url: str, scope: ProgramScope,
                  authorized: bool) -> str:
    """Independent re-derivation of the pre-agent-wiring gate verdict. Returns
    'allow' or 'deny'. Built from the four leash rules, NOT from GuardrailGate,
    so comparing the live gate against it detects any loosening."""
    tool = _resolve_scan_tool(call.tool_name)
    if tool is None or tool not in _AUTO_ORCHESTRATION_TOOLS:
        return "deny"                     # sqlmap / exploitation / unknown
    if not is_target_in_scope(url, scope):
        return "deny"                     # out of scope
    if not authorized:
        return "deny"                     # no authorization record
    return "allow"


# --------------------------------------------------------------------------- #
# P7 core — the gate verdict (and thus the ALLOW set) is UNCHANGED by wiring
# --------------------------------------------------------------------------- #
@settings(max_examples=400, deadline=None)
@given(call=_tool_calls(), url=_urls(), authorized=st.booleans())
def test_p7_gate_verdict_equals_prewiring_oracle(call, url, authorized):
    """For every (call, ctx): live gate ALLOW/DENY == pre-wiring oracle verdict.
    Equivalence in BOTH directions means wiring the target created no new ALLOW
    (韁繩沒鬆) and dropped no existing ALLOW either."""
    ctx = GateContext(target_url=url, scope=_scope(), authorizer=_Auth(authorized))
    verdict = GuardrailGate().check(call, ctx).outcome
    oracle = _leash_oracle(call, url, _scope(), authorized)
    live = "allow" if verdict == GateOutcome.ALLOW else "deny"
    assert live == oracle, (
        f"LEASH DRIFT: gate said {live} but pre-wiring leash says {oracle} — "
        f"tool={call.tool_name!r} url={url!r} authorized={authorized}")


@settings(max_examples=200, deadline=None)
@given(call=_tool_calls(), url=_urls(), authorized=st.booleans())
def test_p7_no_deny_became_allow(call, url, authorized):
    """The targeted invariant you asked to confirm: wiring the target must NOT
    turn any call the pre-wiring leash would DENY into an ALLOW."""
    ctx = GateContext(target_url=url, scope=_scope(), authorizer=_Auth(authorized))
    if _leash_oracle(call, url, _scope(), authorized) == "deny":
        d = GuardrailGate().check(call, ctx)
        assert d.outcome == GateOutcome.DENY, (
            f"LEASH LOOSENED: a pre-wiring DENY became ALLOW after wiring — "
            f"tool={call.tool_name!r} url={url!r} authorized={authorized}")
        assert not d.token, "a DENY must never carry a token"


# --------------------------------------------------------------------------- #
# P7 specifics — sqlmap / out-of-scope / unauthorized stay DENY
# --------------------------------------------------------------------------- #
@settings(max_examples=150, deadline=None)
@given(args=proposed_args, url=_urls(), authorized=st.booleans())
def test_p7_sqlmap_always_denied(args, url, authorized):
    """sqlmap (exploitation) is denied regardless of scope/authorization/args —
    unchanged by wiring."""
    ctx = GateContext(target_url=url, scope=_scope(), authorizer=_Auth(authorized))
    d = GuardrailGate().check(ToolCall("sqlmap", dict(args)), ctx)
    assert d.outcome == GateOutcome.DENY


@settings(max_examples=150, deadline=None)
@given(call=_tool_calls(), authorized=st.booleans())
def test_p7_out_of_scope_denied(call, authorized):
    ctx = GateContext(target_url="https://evil.com/x", scope=_scope(),
                      authorizer=_Auth(authorized))
    d = GuardrailGate().check(call, ctx)
    assert d.outcome == GateOutcome.DENY


@settings(max_examples=150, deadline=None)
@given(call=_tool_calls(), url=_urls())
def test_p7_unauthorized_denied(call, url):
    ctx = GateContext(target_url=url, scope=_scope(), authorizer=_Auth(False))
    d = GuardrailGate().check(call, ctx)
    assert d.outcome == GateOutcome.DENY


# --------------------------------------------------------------------------- #
# P7 — eval-mode args stay FORCED (planner args discarded), unchanged by wiring
# --------------------------------------------------------------------------- #
@settings(max_examples=300, deadline=None)
@given(call=_tool_calls(), authorized=st.booleans())
def test_p7_eval_mode_args_forced(call, authorized):
    ctx = GateContext(target_url="https://app.example.com", scope=_scope(),
                      authorizer=_Auth(authorized))
    d = GuardrailGate().check(call, ctx)
    if d.outcome == GateOutcome.ALLOW:
        tool = _resolve_scan_tool(call.tool_name)
        assert d.call.arguments == list(_EVAL_MODE_ARGS[tool])
        # the planner-proposed (possibly adversarial) args never survive
        assert d.call.arguments != call.arguments or call.arguments == {}


# --------------------------------------------------------------------------- #
# P7 — the one-time token is still consumed EXACTLY once at the server
#      (defense in depth; wiring added a ctx param but must not weaken this)
# --------------------------------------------------------------------------- #
_AUTH_TARGET = "https://app.example.com"


def _ctx():
    return GateContext(target_url=_AUTH_TARGET, scope=_scope(),
                       authorizer=_Auth(True))


class _FixtureSpyEngine:
    """Faithful engine fake: returns empty output (we only care about token
    single-use here); delegates parsing to the real ScanEngine."""
    def __init__(self):
        from app.bounty.scanner import ScanEngine
        self._real = ScanEngine()
        self.calls = 0
    def run_tool(self, tool, target, args, timeout=1800.0):
        self.calls += 1
        return ""
    def _parse_tool_output(self, tool, raw_output, scan_id="", target=""):
        return self._real._parse_tool_output(tool, raw_output, scan_id, target)


@settings(max_examples=120, deadline=None)
@given(token=st.integers(min_value=1, max_value=10**9))
def test_p7_one_time_token_consumed_exactly_once(token):
    """After wiring, invoke(call, approval, ctx) still consumes the one-time
    token exactly once: the first ALLOW dispatches; a second invoke with the
    SAME token is refused (ToolNotApproved) and never reaches the engine."""
    async def _run():
        engine = _FixtureSpyEngine()
        srv = ElianaMCPServer(scan_engine=engine)
        call = ToolCall("nmap", {})
        appr = GateDecision(GateOutcome.ALLOW, call, token=f"tok-{token}")
        await srv.invoke(call, appr, _ctx())            # first: dispatches
        assert engine.calls == 1
        raised = False
        try:
            await srv.invoke(call, appr, _ctx())        # reuse SAME token
        except ToolNotApproved:
            raised = True
        assert raised, "token reuse was not refused after wiring"
        assert engine.calls == 1, "a reused token still reached the engine"
    asyncio.run(_run())
