"""Task 6.2 — unit tests for LocalPlannerLLM parsing + unavailability.

Mocks the local endpoint (no real Ollama). Asserts:
  - a single decision is parsed correctly (INVOKE_TOOL / STOP / malformed->STOP)
  - an unreachable endpoint surfaces PlannerUnavailable (fail-closed, no cloud)
  - the default model is the probe-decided llama3.2:3b
"""
import asyncio
import json

import pytest

from agent_core.eliana.local_planner import (
    LocalPlannerLLM,
    PlannerUnavailable,
    _DEFAULT_MODEL,
)
from agent_core.models import (
    AssessmentGoal,
    DecisionKind,
    PerceivedState,
    ToolSpec,
)
from app.bounty.models import ProgramScope


def _state() -> PerceivedState:
    goal = AssessmentGoal("https://app.example.com",
                          ProgramScope(domains=["app.example.com"]),
                          "assess web_app")
    return PerceivedState(goal=goal, findings_so_far=[], steps_taken=[],
                          available_tools=[ToolSpec("recon_scan", "d")])


def test_default_model_is_probe_decided_3b():
    assert _DEFAULT_MODEL == "llama3.2:3b"
    assert LocalPlannerLLM()._model == "llama3.2:3b"


def test_model_is_configurable_for_8b_path():
    p = LocalPlannerLLM(model="llama3.1:latest")
    assert p._model == "llama3.1:latest"


# --- parsing (pure, no network): patch _chat to return canned content -------- #
def _planner_returning(content: str) -> LocalPlannerLLM:
    p = LocalPlannerLLM()
    p._chat = lambda payload: content  # type: ignore[assignment]
    return p


def test_parse_invoke_tool():
    p = _planner_returning(
        json.dumps({"action": "invoke_tool", "tool": "nmap", "rationale": "r"}))
    d = asyncio.run(p.decide(_state()))
    assert d.kind == DecisionKind.INVOKE_TOOL
    assert d.tool_call.tool_name == "nmap"
    # planner never supplies flags; args empty (gate forces eval-mode args)
    assert d.tool_call.arguments == {}
    assert d.rationale == "r"


def test_parse_stop():
    p = _planner_returning(json.dumps({"action": "stop", "rationale": "done"}))
    d = asyncio.run(p.decide(_state()))
    assert d.kind == DecisionKind.STOP
    assert d.tool_call is None
    assert d.rationale == "done"


def test_parse_no_tool_becomes_stop():
    # action says invoke but no tool given -> honest STOP, not a fabricated call
    p = _planner_returning(json.dumps({"action": "invoke_tool", "rationale": "x"}))
    d = asyncio.run(p.decide(_state()))
    assert d.kind == DecisionKind.STOP


def test_parse_malformed_json_becomes_stop():
    p = _planner_returning("this is not json")
    d = asyncio.run(p.decide(_state()))
    assert d.kind == DecisionKind.STOP


def test_parse_empty_content_becomes_stop():
    p = _planner_returning("")
    d = asyncio.run(p.decide(_state()))
    assert d.kind == DecisionKind.STOP


def test_tool_name_normalized_lowercase():
    p = _planner_returning(
        json.dumps({"action": "invoke_tool", "tool": "NMAP", "rationale": ""}))
    d = asyncio.run(p.decide(_state()))
    assert d.tool_call.tool_name == "nmap"


# --- unavailability: unreachable endpoint -> PlannerUnavailable (no cloud) --- #
def test_unreachable_endpoint_raises_planner_unavailable():
    # point at a closed port; short timeout; must fail closed, not fabricate
    p = LocalPlannerLLM(base_url="http://127.0.0.1:59999", timeout=2.0)
    with pytest.raises(PlannerUnavailable):
        asyncio.run(p.decide(_state()))


def test_connection_error_becomes_planner_unavailable(monkeypatch):
    """A transport-level connection error must be converted to PlannerUnavailable
    by _chat's own handling (fail-closed), never raised raw and never a decision.
    Patch urllib at the transport level so the real _chat error path runs."""
    import agent_core.eliana.local_planner as lp

    def _boom(req, timeout=None):
        raise OSError("connection refused")
    monkeypatch.setattr(lp.urllib.request, "urlopen", _boom)

    p = LocalPlannerLLM()
    with pytest.raises(PlannerUnavailable):
        asyncio.run(p.decide(_state()))
