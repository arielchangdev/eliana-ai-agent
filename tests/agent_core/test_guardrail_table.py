"""Task 3.7 — table-driven unit tests for GuardrailGate.check.

Covers {in / out of scope} × {authorized / not} × {auto-orchestration / sqlmap /
unknown} × {benign / intrusive proposed args}; ALLOW only in the exact-permitted
cell, and ALLOW args always equal _EVAL_MODE_ARGS[tool].
"""
import itertools

import pytest

from app.bounty.models import ProgramScope
from app.bounty.scanner import _EVAL_MODE_ARGS
from app.bounty.enums import ScanTool

from agent_core.guardrail import GuardrailGate
from agent_core.models import GateContext, GateOutcome, ToolCall


class _Auth:
    def __init__(self, ok: bool):
        self._ok = ok
    def is_authorized(self, target_url: str) -> bool:
        return self._ok


_SCOPE = ProgramScope(domains=["app.example.com"])
_IN_SCOPE_URL = "https://app.example.com/path"
_OUT_SCOPE_URL = "https://evil.com/path"

# (label, tool_name, is_auto_orchestration)
_TOOLS = [
    ("auto", "nmap", True),       # an allowlisted assessment tool
    ("sqlmap", "sqlmap", False),  # excluded exploitation tool
    ("unknown", "metasploit", False),  # not a ScanTool at all
]
_ARG_SETS = [
    ("benign", {}),
    ("intrusive", {"args": ["--script=exploit", "--dump"]}),
]


def _cases():
    for in_scope, authorized, (tlabel, tname, is_auto), (alabel, args) in \
            itertools.product([True, False], [True, False], _TOOLS, _ARG_SETS):
        yield (in_scope, authorized, tlabel, tname, is_auto, alabel, args)


@pytest.mark.parametrize(
    "in_scope,authorized,tlabel,tname,is_auto,alabel,args", list(_cases()))
def test_gate_table(in_scope, authorized, tlabel, tname, is_auto, alabel, args):
    url = _IN_SCOPE_URL if in_scope else _OUT_SCOPE_URL
    ctx = GateContext(target_url=url, scope=_SCOPE, authorizer=_Auth(authorized))
    d = GuardrailGate().check(ToolCall(tool_name=tname, arguments=args), ctx)

    # ALLOW iff and only iff: auto-orchestration tool AND in scope AND authorized
    should_allow = is_auto and in_scope and authorized
    if should_allow:
        assert d.outcome == GateOutcome.ALLOW, (
            f"expected ALLOW for {tlabel}/{alabel} scope={in_scope} auth={authorized}")
        # arguments forced to eval-mode regardless of benign/intrusive input
        tool = ScanTool(tname)
        assert d.call.arguments == list(_EVAL_MODE_ARGS[tool])
        assert d.token  # one-time token issued
    else:
        assert d.outcome == GateOutcome.DENY, (
            f"expected DENY for {tlabel}/{alabel} scope={in_scope} auth={authorized}")
        assert d.reason  # DENY carries a non-empty reason
        assert not d.token  # no token on DENY


def test_allow_cell_count_is_exactly_the_permitted_ones():
    """Sanity: across the full table, ALLOW appears only in the auto×in-scope×
    authorized cells (one per arg-set) — i.e. exactly 2 ALLOWs (benign+intrusive),
    both with forced eval-mode args."""
    allows = 0
    for in_scope, authorized, tlabel, tname, is_auto, alabel, args in _cases():
        url = _IN_SCOPE_URL if in_scope else _OUT_SCOPE_URL
        ctx = GateContext(target_url=url, scope=_SCOPE, authorizer=_Auth(authorized))
        d = GuardrailGate().check(ToolCall(tool_name=tname, arguments=args), ctx)
        if d.outcome == GateOutcome.ALLOW:
            allows += 1
            assert d.call.arguments == list(_EVAL_MODE_ARGS[ScanTool.NMAP])
    assert allows == 2, f"expected exactly 2 ALLOW cells, got {allows}"


def test_audit_sink_receives_one_record_per_decision():
    records = []
    gate = GuardrailGate(audit_sink=records.append)
    ctx_ok = GateContext(target_url=_IN_SCOPE_URL, scope=_SCOPE, authorizer=_Auth(True))
    gate.check(ToolCall("nmap"), ctx_ok)          # allow
    gate.check(ToolCall("sqlmap"), ctx_ok)        # deny
    assert len(records) == 2
    assert records[0]["outcome"] == "allow"
    assert records[1]["outcome"] == "deny" and records[1]["reason"]
