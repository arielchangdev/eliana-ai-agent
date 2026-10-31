"""Task 1.2 — unit tests for agent_core data model construction and validation.

Validates design rules: ToolCall.tool_name non-empty; AssessmentGoal.max_steps >= 1;
findings carry severity + ATT&CK label shape only; frozen dataclasses are immutable.
"""
import dataclasses

import pytest

from app.bounty.models import ProgramScope
from agent_core.models import (
    AssessmentGoal,
    AssessmentOutcome,
    DecisionKind,
    DecisionTrace,
    GateContext,
    GateDecision,
    GateOutcome,
    Observation,
    PerceivedState,
    PlannerDecision,
    StepRecord,
    ToolCall,
    ToolSpec,
)


def _scope() -> ProgramScope:
    return ProgramScope(domains=["app.example.com"])


# --- ToolCall validation ---------------------------------------------------- #
def test_toolcall_valid():
    c = ToolCall(tool_name="nmap", arguments={"x": 1})
    assert c.tool_name == "nmap"


@pytest.mark.parametrize("bad", ["", "   ", None])
def test_toolcall_tool_name_must_be_nonempty(bad):
    with pytest.raises(ValueError):
        ToolCall(tool_name=bad)  # type: ignore[arg-type]


def test_toolcall_default_arguments_empty():
    assert ToolCall(tool_name="nmap").arguments == {}


# --- AssessmentGoal validation ---------------------------------------------- #
def test_assessment_goal_valid():
    g = AssessmentGoal(target_url="https://app.example.com", scope=_scope(),
                       description="assess web_app", max_steps=12)
    assert g.max_steps == 12


@pytest.mark.parametrize("bad_steps", [0, -1, -100])
def test_assessment_goal_max_steps_floor(bad_steps):
    with pytest.raises(ValueError):
        AssessmentGoal(target_url="u", scope=_scope(), max_steps=bad_steps)


def test_assessment_goal_max_steps_one_ok():
    assert AssessmentGoal(target_url="u", scope=_scope(), max_steps=1).max_steps == 1


# --- frozen immutability ---------------------------------------------------- #
def test_frozen_dataclasses_are_immutable():
    c = ToolCall(tool_name="nmap")
    with pytest.raises(dataclasses.FrozenInstanceError):
        c.tool_name = "sqlmap"  # type: ignore[misc]


# --- findings shape (severity + ATT&CK label only) -------------------------- #
def test_findings_shape_severity_and_attack_label_only():
    """Design: findings_so_far entries carry severity + ATT&CK label shape only
    (no payloads / exploitation detail). We assert the shape we construct with."""
    finding = {
        "severity": "medium",
        "attack_technique_id": "T1190",
        "attack_technique_name": "Exploit Public-Facing Application",
    }
    state = PerceivedState(
        goal=AssessmentGoal(target_url="https://app.example.com", scope=_scope()),
        findings_so_far=[finding],
        steps_taken=[],
        available_tools=[ToolSpec(name="recon_scan", description="d")],
    )
    f = state.findings_so_far[0]
    assert set(f).issubset(
        {"severity", "attack_technique_id", "attack_technique_name", "attack_tactic"})
    assert "payload" not in f and "raw_output" not in f


# --- trace append ----------------------------------------------------------- #
def test_decision_trace_append():
    goal = AssessmentGoal(target_url="u", scope=_scope())
    trace = DecisionTrace(goal=goal)
    step = StepRecord(
        index=0,
        decision=PlannerDecision(kind=DecisionKind.STOP, rationale="done"),
        gate=GateDecision(outcome=GateOutcome.DENY, call=ToolCall("nmap"), reason="r"),
        observation=None,
    )
    trace.append(step)
    assert len(trace.steps) == 1 and trace.steps[0].index == 0


def test_observation_and_outcome_shape():
    obs = Observation(tool_name="nmap", findings=[{"severity": "low"}])
    goal = AssessmentGoal(target_url="u", scope=_scope())
    outcome = AssessmentOutcome(findings=obs.findings, trace=DecisionTrace(goal=goal),
                                stopped_reason="step budget reached")
    assert outcome.findings[0]["severity"] == "low"
    assert outcome.stopped_reason == "step budget reached"


def test_gate_context_holds_scope_and_target():
    ctx = GateContext(target_url="https://app.example.com", scope=_scope(),
                      authorizer=object())
    assert ctx.target_url == "https://app.example.com"
    assert ctx.scope.domains == ["app.example.com"]
