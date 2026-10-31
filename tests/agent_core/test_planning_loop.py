"""Task 8.4 — unit tests for PlanningLoop.run with scripted fakes.

Asserts trace completeness (one StepRecord per iteration, including DENYs),
STOP handling, fail-closed on planner-unavailable, and the record-on-completion
seam. All dependencies are faked — no Ollama, no Kali, no real scans.
"""
import asyncio

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
    RecordingMemory,
    ScriptedPlanner,
    StubAuthorizer,
    scope,
)


def _goal(max_steps=12):
    return AssessmentGoal("https://app.example.com", scope(),
                          "assess web_app", max_steps=max_steps)


def _invoke(tool="nmap"):
    return PlannerDecision(kind=DecisionKind.INVOKE_TOOL,
                           tool_call=ToolCall(tool_name=tool, arguments={}),
                           rationale=f"try {tool}")


def _stop(reason="done"):
    return PlannerDecision(kind=DecisionKind.STOP, rationale=reason)


# --- STOP handling ---------------------------------------------------------- #
def test_stop_immediately_records_one_step_and_returns():
    planner = ScriptedPlanner([_stop("nothing to do")])
    loop = PlanningLoop(planner, FakeGate("allow"), FakeTools(),
                        StubAuthorizer(True), memory=None, max_steps=12)
    out = asyncio.run(loop.run(_goal()))
    assert out.stopped_reason == "nothing to do"
    assert len(out.trace.steps) == 1
    assert out.trace.steps[0].decision.kind == DecisionKind.STOP
    assert out.trace.steps[0].observation is None
    assert out.findings == []


# --- trace completeness incl. DENY ------------------------------------------ #
def test_trace_has_one_step_per_iteration_including_denies():
    # sqlmap will be DENYed by the fake gate ('deny' mode), 3 attempts then budget
    planner = ScriptedPlanner([_invoke("sqlmap"), _invoke("sqlmap"), _invoke("sqlmap")],
                              stop_when_done=False)
    tools = FakeTools()
    loop = PlanningLoop(planner, FakeGate("deny"), tools, StubAuthorizer(True),
                        memory=None, max_steps=3)
    out = asyncio.run(loop.run(_goal(max_steps=3)))
    # one StepRecord per iteration (3), all DENY, none with an observation
    assert len(out.trace.steps) == 3
    assert all(s.gate.outcome == GateOutcome.DENY for s in out.trace.steps)
    assert all(s.observation is None for s in out.trace.steps)
    # DENY never reached the tool server
    assert tools.invoke_calls == 0
    assert out.stopped_reason == "step budget reached"


def test_mixed_allow_and_deny_trace():
    # allow nmap, deny sqlmap, then allow nikto — fake gate allows by a predicate
    def allow_non_sqlmap(call, ctx):
        return call.tool_name != "sqlmap"
    planner = ScriptedPlanner([_invoke("nmap"), _invoke("sqlmap"), _invoke("nikto"),
                               _stop("done")])
    tools = FakeTools(findings_per_call=[{"severity": "info", "source": "tool"}])
    loop = PlanningLoop(planner, FakeGate(allow_non_sqlmap), tools,
                        StubAuthorizer(True), memory=None, max_steps=12)
    out = asyncio.run(loop.run(_goal()))
    kinds = [(s.gate.outcome.value, s.observation is not None) for s in out.trace.steps]
    # nmap ALLOW+obs, sqlmap DENY+no obs, nikto ALLOW+obs, then STOP (deny-placeholder,no obs)
    assert kinds == [("allow", True), ("deny", False), ("allow", True), ("deny", False)]
    assert tools.invoke_calls == 2         # only the two ALLOWs ran
    assert len(out.findings) == 2          # one finding per ALLOWed invoke


# --- ALLOW carries a token that the tools layer sees ------------------------ #
def test_invoke_only_receives_allow_with_token():
    planner = ScriptedPlanner([_invoke("nmap"), _stop()])
    tools = FakeTools()
    loop = PlanningLoop(planner, FakeGate("allow"), tools, StubAuthorizer(True),
                        memory=None, max_steps=12)
    asyncio.run(loop.run(_goal()))
    assert tools.invoke_calls == 1
    assert tools.seen_tokens and all(t for t in tools.seen_tokens)  # non-empty token


# --- no-new-information stop ------------------------------------------------ #
def test_no_new_information_stops():
    planner = ScriptedPlanner([_invoke("nmap"), _invoke("nmap")], stop_when_done=False)
    tools = EmptyTools()  # invoke returns no findings
    loop = PlanningLoop(planner, FakeGate("allow"), tools, StubAuthorizer(True),
                        memory=None, max_steps=12)
    out = asyncio.run(loop.run(_goal()))
    # first invoke yields no findings -> stop after one step
    assert out.stopped_reason == "no further progress"
    assert len(out.trace.steps) == 1
    assert tools.invoke_calls == 1


# --- fail closed on planner unavailable ------------------------------------- #
def test_fail_closed_on_planner_unavailable():
    tools = FakeTools()
    loop = PlanningLoop(DeadPlanner(), FakeGate("allow"), tools,
                        StubAuthorizer(True), memory=None, max_steps=12)
    out = asyncio.run(loop.run(_goal()))
    assert out.stopped_reason == PLANNER_UNAVAILABLE_REASON
    assert out.findings == []
    assert len(out.trace.steps) == 0
    # fail-closed: NO tool was ever invoked
    assert tools.invoke_calls == 0


# --- record experience on normal completion -------------------------------- #
def test_records_experience_on_completion():
    mem = RecordingMemory()
    planner = ScriptedPlanner([_invoke("nmap")], stop_when_done=False)
    tools = FakeTools(findings_per_call=[{"severity": "info", "source": "tool"}])
    loop = PlanningLoop(planner, FakeGate("allow"), tools, StubAuthorizer(True),
                        memory=mem, max_steps=1)
    out = asyncio.run(loop.run(_goal(max_steps=1)))
    assert out.stopped_reason == "step budget reached"
    assert mem.recorded is not None
    assert mem.recorded["tools_used"] == ["nmap"]


def test_no_record_on_planner_unavailable():
    mem = RecordingMemory()
    loop = PlanningLoop(DeadPlanner(), FakeGate("allow"), FakeTools(),
                        StubAuthorizer(True), memory=mem, max_steps=5)
    asyncio.run(loop.run(_goal()))
    # fail-closed path returns before recording
    assert mem.recorded is None


def test_budget_capped_by_min_of_goal_and_loop():
    # goal.max_steps=2 but loop max_steps=10 -> effective budget 2
    planner = ScriptedPlanner([], stop_when_done=False)  # never stops
    loop = PlanningLoop(planner, FakeGate("allow"), FakeTools(), StubAuthorizer(True),
                        memory=None, max_steps=10)
    out = asyncio.run(loop.run(_goal(max_steps=2)))
    assert planner.decide_calls == 2
    assert len(out.trace.steps) == 2
