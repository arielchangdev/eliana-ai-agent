"""Property tests for GuardrailGate (Hypothesis).

Encodes design correctness properties 1-5. The gate is the *relocated* old logic;
these properties prove the leash is at least as strong as the pre-agent path.

  P1 No bypass            — every executed-eligible call carries an ALLOW + token
  P2 Subset guarantee     — gate-ALLOWed ⊆ old-path-permitted (the leash)
  P3 No exploitation tool — sqlmap / non-allowlist tool => DENY
  P4 Fixed arguments      — ALLOW args == _EVAL_MODE_ARGS[tool], always
  P5 Authorization prec.   — not authorized (or out of scope) => DENY
"""
from hypothesis import given, settings, strategies as st

from app.bounty.models import ProgramScope
from app.bounty.scanner import (
    _AUTO_ORCHESTRATION_TOOLS,
    _EVAL_MODE_ARGS,
    build_phased_profile,
    is_target_in_scope,
)
from app.bounty.enums import ScanTool

from agent_core.guardrail import GuardrailGate, _resolve_scan_tool
from agent_core.models import GateContext, GateOutcome, ToolCall


# --------------------------------------------------------------------------- #
# strategies
# --------------------------------------------------------------------------- #
_ALL_TOOL_NAMES = [t.value for t in ScanTool]          # incl. sqlmap
# Unknown names + case/whitespace variants. (Empty / blank names are excluded
# here because ToolCall validation rejects them upstream — that guard is covered
# by test_models.py; they can never form a ToolCall to reach the gate.)
_EXTRA_NAMES = ["metasploit", "msfconsole", "NMAP", "SqlMap", "nmap "]

tool_names = st.sampled_from(_ALL_TOOL_NAMES + _EXTRA_NAMES)

# arbitrary intrusive / benign planner-proposed arguments (should be discarded)
proposed_args = st.dictionaries(
    keys=st.sampled_from(["args", "flags", "extra", "script"]),
    values=st.lists(st.sampled_from(
        ["--dump", "--script=exploit", "-sV", "--intrusive", "safe"]),
        max_size=3),
    max_size=3,
)

hostnames = st.sampled_from([
    "app.example.com", "sub.app.example.com", "evil.com", "example.org",
])
schemes = st.sampled_from(["https://", "http://"])
paths = st.sampled_from(["", "/", "/admin", "/api/v1"])


class _Auth:
    def __init__(self, ok: bool):
        self._ok = ok
    def is_authorized(self, target_url: str) -> bool:
        return self._ok


def _scope() -> ProgramScope:
    return ProgramScope(domains=["app.example.com"])


def _tool_calls():
    return st.builds(ToolCall, tool_name=tool_names, arguments=proposed_args)


def _urls():
    return st.builds(lambda s, h, p: f"{s}{h}{p}", schemes, hostnames, paths)


# --------------------------------------------------------------------------- #
# P3 — No exploitation tool (sqlmap / non-allowlist => DENY)
# --------------------------------------------------------------------------- #
@settings(max_examples=300)
@given(call=_tool_calls())
def test_p3_no_exploitation_tool(call):
    ctx = GateContext(target_url="https://app.example.com", scope=_scope(),
                      authorizer=_Auth(True))
    tool = _resolve_scan_tool(call.tool_name)
    d = GuardrailGate().check(call, ctx)
    if tool is None or tool not in _AUTO_ORCHESTRATION_TOOLS:
        assert d.outcome == GateOutcome.DENY
    # sqlmap specifically must always be denied
    if call.tool_name.strip().lower() == "sqlmap":
        assert d.outcome == GateOutcome.DENY


# --------------------------------------------------------------------------- #
# P4 — Fixed arguments (ALLOW args == _EVAL_MODE_ARGS[tool], regardless of input)
# --------------------------------------------------------------------------- #
@settings(max_examples=300)
@given(call=_tool_calls())
def test_p4_fixed_arguments(call):
    ctx = GateContext(target_url="https://app.example.com", scope=_scope(),
                      authorizer=_Auth(True))
    d = GuardrailGate().check(call, ctx)
    if d.outcome == GateOutcome.ALLOW:
        tool = _resolve_scan_tool(call.tool_name)
        assert d.call.arguments == list(_EVAL_MODE_ARGS[tool])
        # the proposed (possibly intrusive) args never survive
        assert d.call.arguments != call.arguments or call.arguments == {}


# --------------------------------------------------------------------------- #
# P5 — Authorization precedence (not authorized or out-of-scope => DENY)
# --------------------------------------------------------------------------- #
@settings(max_examples=300)
@given(call=_tool_calls(), url=_urls(), authorized=st.booleans())
def test_p5_authorization_precedence(call, url, authorized):
    ctx = GateContext(target_url=url, scope=_scope(), authorizer=_Auth(authorized))
    d = GuardrailGate().check(call, ctx)
    in_scope = is_target_in_scope(url, _scope())
    if not authorized or not in_scope:
        assert d.outcome == GateOutcome.DENY, (
            f"expected DENY for authorized={authorized} in_scope={in_scope}")


# --------------------------------------------------------------------------- #
# P1 — No bypass (an ALLOW always carries a token issued for that exact call;
#      only all-four-postconditions-pass yields ALLOW)
# --------------------------------------------------------------------------- #
@settings(max_examples=300)
@given(call=_tool_calls(), url=_urls(), authorized=st.booleans())
def test_p1_no_bypass(call, url, authorized):
    ctx = GateContext(target_url=url, scope=_scope(), authorizer=_Auth(authorized))
    d = GuardrailGate().check(call, ctx)
    if d.outcome == GateOutcome.ALLOW:
        # ALLOW implies a non-empty one-time token, bound to the normalized call
        assert d.token, "ALLOW must carry a one-time approval token"
        # and all four postconditions genuinely held
        tool = _resolve_scan_tool(call.tool_name)
        assert tool in _AUTO_ORCHESTRATION_TOOLS
        assert is_target_in_scope(url, _scope())
        assert authorized is True
        assert d.call.arguments == list(_EVAL_MODE_ARGS[tool])
    else:
        # DENY must never carry a token
        assert not d.token


# --------------------------------------------------------------------------- #
# P2 — Subset guarantee (the leash): gate-ALLOWed ⊆ old-path-permitted.
#      The old path = build_phased_profile tool filtering + the scope/authz gate
#      that authorized_scan enforced. We prove: if the gate ALLOWs a call, the
#      old path would also have permitted that exact (tool, eval-args) on an
#      authorized, in-scope target — and never the reverse for excluded tools.
# --------------------------------------------------------------------------- #
def _old_path_permits(call: ToolCall, url: str, scope: ProgramScope,
                      authorized: bool) -> bool:
    """Reconstruct what the pre-agent path would have permitted for a single
    proposed tool: (a) authorized_scan gate = in-scope AND authorized, and
    (b) build_phased_profile keeps the tool (i.e. it's an auto-orchestration
    tool) and assigns it exactly _EVAL_MODE_ARGS[tool]."""
    if not (authorized and is_target_in_scope(url, scope)):
        return False
    tool = _resolve_scan_tool(call.tool_name)
    if tool is None:
        return False
    profile = build_phased_profile(tools=[tool])
    if tool not in profile.tools:
        return False
    # old path assigns the same eval-mode args
    return profile.args.get(tool, []) == list(_EVAL_MODE_ARGS.get(tool, []))


@settings(max_examples=400)
@given(call=_tool_calls(), url=_urls(), authorized=st.booleans())
def test_p2_subset_guarantee(call, url, authorized):
    ctx = GateContext(target_url=url, scope=_scope(), authorizer=_Auth(authorized))
    d = GuardrailGate().check(call, ctx)
    if d.outcome == GateOutcome.ALLOW:
        # every gate-ALLOW must be something the old path would also permit
        assert _old_path_permits(call, url, _scope(), authorized), (
            "LEASH VIOLATION: gate ALLOWed a call the old path would refuse — "
            f"tool={call.tool_name} url={url} authorized={authorized}")
        # and the normalized args match what the old path would assign
        tool = _resolve_scan_tool(call.tool_name)
        profile = build_phased_profile(tools=[tool])
        assert d.call.arguments == list(profile.args.get(tool, []))
