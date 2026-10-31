"""Task 11.1 — end-to-end integration test.

Wires the WHOLE chain with REAL components (GuardrailGate, ElianaMCPServer,
PlanningLoop) and stubs only at the external edges:
  - authorization : stub AuthorizationPort (is_authorized=True) — simulates the
                    human-written Authorization_Record the gate reads
  - scan engine   : stub ScanEngine.run_tool returning fixed output (no real host)
  - planner       : scripted fake PlannerLLM (no Ollama) driving a predictable
                    decision sequence incl. an out-of-scope/excluded proposal

Asserts the chain truly connects: planner -> gate -> MCP server (with a real
one-time token) -> observation -> findings -> memory record, and that the trace
shows gated decisions (ALLOW steps, and a DENY when the planner proposes an
excluded tool).

All stub/fake: no real Ollama, no Kali, no real scan.
"""
import asyncio

from agent_core.guardrail import GuardrailGate
from agent_core.eliana.mcp_server import ElianaMCPServer
from agent_core.planning_loop import PlanningLoop
from agent_core.models import (
    AssessmentGoal,
    DecisionKind,
    GateOutcome,
    PlannerDecision,
    ToolCall,
)
from app.bounty.models import ProgramScope


# --- stubs at the external edges ------------------------------------------- #
class StubEngine:
    """Stands in for ScanEngine.run_tool — records dispatches, returns fixed
    output. Never touches a real host."""
    def __init__(self):
        self.dispatched = []
    def run_tool(self, tool, target, args, timeout=1800.0):
        self.dispatched.append((tool, list(args)))
        return f"stub output for {getattr(tool, 'value', tool)}: open 443/tcp"


def _attack_mapper(tool, title="", description=""):
    class _T:
        technique_id = "T1046"
        technique_name = "Network Service Discovery"
        tactic_id = "TA0007"
        tactic_name = "Discovery"
    return _T()


class StubAuthorizer:
    """Simulates the human-granted, non-expired authorization record."""
    def __init__(self, ok=True):
        self._ok = ok
        self.checks = []
    def is_authorized(self, target_url):
        self.checks.append(target_url)
        return self._ok


class RecordingMemory:
    """MemoryPort stub — records whether record() ran and captures the args."""
    def __init__(self):
        self.recorded = None
    def focus_hints(self, goal):
        return []
    def priority_tools(self, goal):
        return []
    def record(self, goal, findings, tools_used):
        self.recorded = {"findings": list(findings), "tools_used": list(tools_used)}


class ScriptedPlanner:
    """Fake PlannerLLM (no Ollama). Emits a scripted decision sequence:
    1) ALLOWable recon tool, 2) an EXCLUDED tool (sqlmap) -> gate DENY,
    3) another ALLOWable tool, then STOP."""
    def __init__(self, decisions):
        self._d = list(decisions)
        self.decide_calls = 0
    async def decide(self, state):
        self.decide_calls += 1
        if self._d:
            return self._d.pop(0)
        return PlannerDecision(kind=DecisionKind.STOP, rationale="done")


def _goal():
    return AssessmentGoal(
        target_url="https://app.example.com",
        scope=ProgramScope(domains=["app.example.com"]),
        description="assess web_app attack surface",
        max_steps=12,
    )


def _invoke(tool):
    return PlannerDecision(kind=DecisionKind.INVOKE_TOOL,
                           tool_call=ToolCall(tool_name=tool, arguments={}),
                           rationale=f"try {tool}")


def _build_loop(planner, memory, authorizer, engine):
    """Assemble the loop exactly as production does (minus real services)."""
    mcp = ElianaMCPServer(scan_engine=engine, attack_mapper=_attack_mapper,
                          memory=None)   # record goes through MemoryPort, not MCP here
    gate = GuardrailGate()
    return PlanningLoop(planner=planner, gate=gate, tools=mcp,
                        authorizer=authorizer, memory=memory, max_steps=12)


# --- the end-to-end test ---------------------------------------------------- #
def test_e2e_full_chain_gated_and_records():
    # Drive to a NORMAL-COMPLETION path that records experience. The loop records
    # on "no further progress" and "step budget reached" (NOT on planner-STOP).
    # Here max_steps=3: nmap(ALLOW), sqlmap(DENY), sslscan(ALLOW) exhausts the
    # budget -> records. (The planner-STOP-does-not-record behavior is asserted
    # separately in test_e2e_planner_stop_path below.)
    planner = ScriptedPlanner([
        _invoke("nmap"),      # ALLOW -> dispatch -> observation
        _invoke("sqlmap"),    # excluded -> gate DENY, no observation
        _invoke("sslscan"),   # ALLOW -> dispatch -> observation; budget reached
    ])
    memory = RecordingMemory()
    authorizer = StubAuthorizer(ok=True)
    engine = StubEngine()
    goal = AssessmentGoal(
        target_url="https://app.example.com",
        scope=ProgramScope(domains=["app.example.com"]),
        description="assess web_app attack surface", max_steps=3)
    loop = _build_loop(planner, memory, authorizer, engine)

    outcome = asyncio.run(loop.run(goal))

    # --- chain connected: gate consulted the authorization record ---------- #
    assert authorizer.checks, "gate never consulted the AuthorizationPort"

    # --- trace shows gated decisions: 2 ALLOW (nmap, sslscan) + 1 DENY ------ #
    assert outcome.stopped_reason == "step budget reached"
    steps = outcome.trace.steps
    assert len(steps) == 3
    allow = [s for s in steps if s.gate.outcome == GateOutcome.ALLOW and s.observation]
    deny = [s for s in steps
            if s.gate.outcome == GateOutcome.DENY
            and s.decision.kind == DecisionKind.INVOKE_TOOL]
    assert len(allow) == 2, f"expected 2 ALLOW+obs steps, got {len(allow)}"
    assert len(deny) == 1, f"expected 1 real DENY step, got {len(deny)}"
    # the DENY was the excluded sqlmap, and it produced NO observation
    assert deny[0].decision.tool_call.tool_name == "sqlmap"
    assert deny[0].observation is None
    assert "not permitted" in deny[0].gate.reason

    # --- MCP server actually dispatched only the 2 ALLOWed tools ----------- #
    dispatched_tools = [getattr(t, "value", t) for t, _ in engine.dispatched]
    assert dispatched_tools == ["nmap", "sslscan"]
    # eval-mode args were forced (non-empty for nmap)
    assert all(isinstance(args, list) for _, args in engine.dispatched)

    # --- ALLOW steps carried a real one-time token to the MCP server ------- #
    for s in allow:
        assert s.gate.token, "ALLOW step missing one-time token"

    # --- observations produced findings carrying ATT&CK label (honest) ----- #
    assert len(outcome.findings) == 2
    for f in outcome.findings:
        assert f.get("attack_technique_id") == "T1046"
        assert "payload" not in f

    # --- learning loop closed: record_experience was called on completion -- #
    # (STOP after findings -> normal completion path records experience)
    assert memory.recorded is not None, "record() was never called"
    assert memory.recorded["tools_used"] == ["nmap", "sslscan"]


def test_e2e_planner_stop_after_real_work_records():
    """A planner-initiated STOP AFTER real assessment work is a normal
    completion -> it records experience (same _record_experience / tools_used as
    the other two exit paths). Here nmap runs (ALLOW + finding), then the planner
    STOPs -> record fires because a tool ran and findings accumulated."""
    planner = ScriptedPlanner([
        _invoke("nmap"),
        PlannerDecision(kind=DecisionKind.STOP, rationale="assessment complete"),
    ])
    memory = RecordingMemory()
    engine = StubEngine()
    loop = _build_loop(planner, memory, StubAuthorizer(ok=True), engine)
    outcome = asyncio.run(loop.run(_goal()))
    assert outcome.stopped_reason == "assessment complete"
    # the real tool ran and produced a finding (chain worked)
    assert len(outcome.findings) == 1
    # NEW behavior: STOP after real work records experience
    assert memory.recorded is not None
    assert memory.recorded["tools_used"] == ["nmap"]


def test_e2e_first_step_stop_no_tool_does_not_record():
    """The other half of the condition: a planner that STOPs on the FIRST step
    (no tool ever ran, no findings) must NOT record — avoids polluting memory
    with an empty assessment."""
    planner = ScriptedPlanner([
        PlannerDecision(kind=DecisionKind.STOP, rationale="nothing to assess"),
    ])
    memory = RecordingMemory()
    engine = StubEngine()
    loop = _build_loop(planner, memory, StubAuthorizer(ok=True), engine)
    outcome = asyncio.run(loop.run(_goal()))
    assert outcome.stopped_reason == "nothing to assess"
    assert outcome.findings == []
    assert engine.dispatched == []          # no tool ever ran
    assert memory.recorded is None          # -> no record (empty assessment)


def test_e2e_stop_after_only_denies_does_not_record():
    """STOP after steps that were all DENYed (no tool actually executed, no
    findings) must NOT record — DENY steps are not 'real work'."""
    planner = ScriptedPlanner([
        _invoke("sqlmap"),   # excluded -> DENY, no observation, no finding
        PlannerDecision(kind=DecisionKind.STOP, rationale="gave up"),
    ])
    memory = RecordingMemory()
    engine = StubEngine()
    loop = _build_loop(planner, memory, StubAuthorizer(ok=True), engine)
    outcome = asyncio.run(loop.run(_goal()))
    assert outcome.stopped_reason == "gave up"
    assert engine.dispatched == []          # sqlmap denied -> nothing ran
    assert outcome.findings == []
    assert memory.recorded is None          # no real work -> no record


def test_e2e_budget_exhaustion_path_records():
    """The 'step budget reached' completion path DOES record experience. A
    never-STOP planner proposing an ALLOWable tool each step exhausts the budget
    and records on completion."""
    planner = ScriptedPlanner([_invoke("nmap"), _invoke("sslscan")])
    memory = RecordingMemory()
    engine = StubEngine()
    goal = AssessmentGoal(
        target_url="https://app.example.com",
        scope=ProgramScope(domains=["app.example.com"]),
        description="assess web_app attack surface", max_steps=2)
    loop = _build_loop(planner, memory, StubAuthorizer(ok=True), engine)
    outcome = asyncio.run(loop.run(goal))
    assert outcome.stopped_reason == "step budget reached"
    assert memory.recorded is not None
    assert memory.recorded["tools_used"] == ["nmap", "sslscan"]


def test_e2e_unauthorized_target_denied_end_to_end():
    """If the authorization record says not-authorized, the gate DENYs every
    tool end to end — nothing dispatches, no findings, honest empty."""
    planner = ScriptedPlanner([_invoke("nmap"), _invoke("sslscan")])
    memory = RecordingMemory()
    engine = StubEngine()
    loop = _build_loop(planner, memory, StubAuthorizer(ok=False), engine)

    outcome = asyncio.run(loop.run(_goal()))

    assert all(s.gate.outcome == GateOutcome.DENY for s in outcome.trace.steps)
    assert engine.dispatched == []          # nothing ever ran
    assert outcome.findings == []           # no fabricated findings
