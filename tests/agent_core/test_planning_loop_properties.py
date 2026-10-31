"""Property tests for PlanningLoop (Hypothesis).

  P6 Termination     — for any max_steps>=1 and any (incl. adversarial) planner,
                       run halts within max_steps planner invocations.
  P7 Honest findings — every finding in outcome.findings traces to an executed,
                       ALLOWed tool; the planner cannot inject findings; DENYs
                       never produce observations.
"""
import asyncio

from hypothesis import given, settings, strategies as st

from agent_core.planning_loop import PlanningLoop, PLANNER_UNAVAILABLE_REASON
from agent_core.models import (
    AssessmentGoal,
    DecisionKind,
    GateOutcome,
    PlannerDecision,
    ToolCall,
)

from tests.agent_core.loop_fakes import (
    DeadPlanner,
    EmptyTools,
    FakeGate,
    FakeTools,
    ScriptedPlanner,
    StubAuthorizer,
    scope,
)


def _goal(max_steps: int) -> AssessmentGoal:
    return AssessmentGoal("https://app.example.com", scope(),
                          "assess web_app", max_steps=max_steps)


# --------------------------------------------------------------------------- #
# P6 — Termination
# --------------------------------------------------------------------------- #
# adversarial decision generator: random mix of STOP / INVOKE(various tools,
# including excluded/unknown ones), so the planner may try to run forever.
_tool_names = st.sampled_from(
    ["nmap", "nikto", "nuclei", "sslscan", "gobuster", "sqlmap", "metasploit"])
_decisions = st.lists(
    st.one_of(
        st.builds(lambda t: PlannerDecision(
            kind=DecisionKind.INVOKE_TOOL,
            tool_call=ToolCall(tool_name=t, arguments={}),
            rationale="x"), _tool_names),
        st.just(PlannerDecision(kind=DecisionKind.STOP, rationale="stop")),
    ),
    max_size=30,
)


@settings(max_examples=200, deadline=None)
@given(max_steps=st.integers(min_value=1, max_value=20),
       decisions=_decisions,
       gate_mode=st.sampled_from(["allow", "deny"]),
       empty=st.booleans())
def test_p6_termination(max_steps, decisions, gate_mode, empty):
    # stop_when_done=False makes the planner adversarial: when the scripted list
    # runs out it keeps proposing a tool forever (never self-stops).
    planner = ScriptedPlanner(decisions, stop_when_done=False)
    tools = EmptyTools() if empty else FakeTools()
    loop = PlanningLoop(planner, FakeGate(gate_mode), tools, StubAuthorizer(True),
                        memory=None, max_steps=max_steps)
    outcome = asyncio.run(loop.run(_goal(max_steps)))

    # TERMINATION: planner was invoked at most max_steps times (budget cap).
    assert planner.decide_calls <= max_steps
    # and the trace never exceeds the budget
    assert len(outcome.trace.steps) <= max_steps
    # the run returned an outcome with a stop reason (it halted)
    assert isinstance(outcome.stopped_reason, str) and outcome.stopped_reason


@settings(max_examples=50, deadline=None)
@given(max_steps=st.integers(min_value=1, max_value=20))
def test_p6_termination_adversarial_never_stops(max_steps):
    """Planner that NEVER emits STOP and always proposes an ALLOWable tool — the
    loop must still halt at the step budget."""
    planner = ScriptedPlanner([], stop_when_done=False)  # infinite INVOKE(nmap)
    loop = PlanningLoop(planner, FakeGate("allow"), FakeTools(), StubAuthorizer(True),
                        memory=None, max_steps=max_steps)
    outcome = asyncio.run(loop.run(_goal(max_steps)))
    assert planner.decide_calls <= max_steps
    assert len(outcome.trace.steps) <= max_steps


@settings(max_examples=30, deadline=None)
@given(max_steps=st.integers(min_value=1, max_value=20))
def test_p6_termination_planner_unavailable(max_steps):
    """Fail-closed path also terminates (immediately)."""
    loop = PlanningLoop(DeadPlanner(), FakeGate("allow"), FakeTools(),
                        StubAuthorizer(True), memory=None, max_steps=max_steps)
    outcome = asyncio.run(loop.run(_goal(max_steps)))
    assert outcome.stopped_reason == PLANNER_UNAVAILABLE_REASON
    assert len(outcome.trace.steps) == 0  # stopped before any step recorded


# --------------------------------------------------------------------------- #
# P7 — Honest findings
# --------------------------------------------------------------------------- #
# A sentinel finding the TOOL returns. The planner never produces findings — it
# only produces decisions/rationales — so if a finding appears in the outcome it
# MUST have come from a tool invoke.
_TOOL_FINDING = {"severity": "medium", "attack_technique_id": "T1190",
                 "source": "tool"}


@settings(max_examples=200, deadline=None)
@given(max_steps=st.integers(min_value=1, max_value=12),
       decisions=_decisions,
       gate_mode=st.sampled_from(["allow", "deny"]))
def test_p7_honest_findings(max_steps, decisions, gate_mode):
    planner = ScriptedPlanner(decisions, stop_when_done=True)
    tools = FakeTools(findings_per_call=[_TOOL_FINDING])
    gate = FakeGate(gate_mode)
    loop = PlanningLoop(planner, gate, tools, StubAuthorizer(True),
                        memory=None, max_steps=max_steps)
    outcome = asyncio.run(loop.run(_goal(max_steps)))

    # 1. Every finding is the TOOL's sentinel — none fabricated by the planner.
    for f in outcome.findings:
        assert f == _TOOL_FINDING, f"non-tool finding leaked into outcome: {f}"

    # 2. finding count == number of ALLOWed invocations (each invoke yields one
    #    sentinel). Executed calls ⊆ allowed calls.
    allow_steps = [s for s in outcome.trace.steps
                   if s.gate.outcome == GateOutcome.ALLOW and s.observation is not None]
    assert len(outcome.findings) == len(allow_steps) * len(tools._findings)
    assert len(allow_steps) == tools.invoke_calls

    # 3. Gate invariant: no DENY step ever carries an observation.
    for s in outcome.trace.steps:
        if s.gate.outcome == GateOutcome.DENY:
            assert s.observation is None
    # 4. If the gate denied everything, nothing ran and there are no findings.
    if gate_mode == "deny":
        assert tools.invoke_calls == 0
        assert outcome.findings == []


@settings(max_examples=100, deadline=None)
@given(max_steps=st.integers(min_value=1, max_value=12))
def test_p7_planner_cannot_inject_findings_via_rationale(max_steps):
    """Even if the planner stuffs 'findings' into its rationale/decision, the
    loop only ever appends observation.findings from the tool."""
    # planner proposes a tool whose decision rationale screams fake findings
    poison = PlannerDecision(
        kind=DecisionKind.INVOKE_TOOL,
        tool_call=ToolCall(tool_name="nmap", arguments={"findings": [{"severity": "critical", "source": "planner-injected"}]}),
        rationale="findings: critical RCE everywhere (planner-claimed)")
    planner = ScriptedPlanner([poison], stop_when_done=True)
    tools = FakeTools(findings_per_call=[_TOOL_FINDING])
    loop = PlanningLoop(planner, FakeGate("allow"), tools, StubAuthorizer(True),
                        memory=None, max_steps=max_steps)
    outcome = asyncio.run(loop.run(_goal(max_steps)))
    # the planner-injected finding must NOT appear; only the tool's finding can
    assert all(f.get("source") != "planner-injected" for f in outcome.findings)
    for f in outcome.findings:
        assert f == _TOOL_FINDING
