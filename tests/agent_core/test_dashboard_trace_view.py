"""Task 10.3 — unit tests for the read-only DecisionTrace dashboard view.

The render logic lives in agent_core.trace_registry.render_latest() (the thin
dashboard wrapper real_adapter.real_decision_trace_provider just delegates to
it). Testing render_latest() directly keeps this unit test free of the dashboard
framework dependency (real_adapter imports app.dashboard.* which is not part of
this repo).

Asserts:
  - renders ALLOW and DENY steps from a trace
  - READ-ONLY: rendering does not mutate the trace or registry
  - no trace (cross-process production case) -> available=False, empty steps,
    never an error, never fabricated data
"""
from agent_core import trace_registry
from agent_core.models import (
    AssessmentGoal,
    DecisionKind,
    DecisionTrace,
    GateDecision,
    GateOutcome,
    Observation,
    PlannerDecision,
    StepRecord,
    ToolCall,
)
from app.bounty.models import ProgramScope

import pytest


@pytest.fixture(autouse=True)
def _clear_registry():
    trace_registry.clear()
    yield
    trace_registry.clear()


def _goal():
    return AssessmentGoal("https://app.example.com",
                          ProgramScope(domains=["app.example.com"]),
                          "assess web_app")


def _trace_with_allow_and_deny() -> DecisionTrace:
    trace = DecisionTrace(goal=_goal())
    trace.append(StepRecord(
        index=0,
        decision=PlannerDecision(DecisionKind.INVOKE_TOOL, ToolCall("nmap", {}), "recon"),
        gate=GateDecision(GateOutcome.ALLOW, ToolCall("nmap", {}), token="tok-1"),
        observation=Observation(tool_name="nmap", findings=[{"severity": "info"}]),
    ))
    trace.append(StepRecord(
        index=1,
        decision=PlannerDecision(DecisionKind.INVOKE_TOOL, ToolCall("sqlmap", {}), "try sqlmap"),
        gate=GateDecision(GateOutcome.DENY, ToolCall("sqlmap", {}),
                          reason="tool not permitted for autonomous use: sqlmap"),
        observation=None,
    ))
    return trace


# --- honest empty when no trace (cross-process production case) -------------- #
def test_no_trace_returns_available_false_not_error():
    view = trace_registry.render_latest()
    assert view["available"] is False
    assert view["steps"] == []
    assert "no agent trace available" in view["reason"]


# --- renders ALLOW and DENY steps ------------------------------------------- #
def test_renders_allow_and_deny_steps():
    trace_registry.publish(_trace_with_allow_and_deny())
    view = trace_registry.render_latest()
    assert view["available"] is True
    assert view["target"] == "https://app.example.com"
    assert len(view["steps"]) == 2
    assert view["allow_count"] == 1
    assert view["deny_count"] == 1

    allow_step, deny_step = view["steps"][0], view["steps"][1]
    assert allow_step["gate"] == "allow"
    assert allow_step["tool"] == "nmap"
    assert allow_step["has_observation"] is True
    assert deny_step["gate"] == "deny"
    assert deny_step["tool"] == "sqlmap"
    assert deny_step["has_observation"] is False
    assert "not permitted" in deny_step["gate_reason"]


# --- read-only: viewing does not mutate the trace or registry --------------- #
def test_view_is_read_only():
    original = _trace_with_allow_and_deny()
    trace_registry.publish(original)
    steps_before = len(original.steps)

    v1 = trace_registry.render_latest()
    v2 = trace_registry.render_latest()

    # underlying trace unchanged; registry still returns the SAME object
    assert len(original.steps) == steps_before
    assert trace_registry.get_latest() is original
    # repeated reads are stable / identical
    assert v1 == v2


# --- the dashboard wrapper delegates to render_latest (no behavior of its own) #
def test_render_latest_is_the_single_source_of_the_view():
    # empty case
    assert trace_registry.render_latest()["available"] is False
    # populated case toggles available True with the same step count
    trace_registry.publish(_trace_with_allow_and_deny())
    v = trace_registry.render_latest()
    assert v["available"] is True and len(v["steps"]) == 2
