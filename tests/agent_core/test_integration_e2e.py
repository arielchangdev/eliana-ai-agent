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


from app.bounty.scanner import ScanEngine
from app.bounty.enums import ScanTool
import tests.agent_core.tool_output_fixtures as fx


# --- stubs at the external edges ------------------------------------------- #
class StubEngine:
    """Faithful ScanEngine fake — records dispatches and returns a REAL captured
    fixture for the dispatched tool (so the rewritten _parse_recon_output
    exercises the real legacy parser). _parse_tool_output delegates to the real
    ScanEngine (no reinvention). Records the target it saw so the e2e can assert
    the authorized target reached the engine. Never touches a real host."""
    def __init__(self):
        self.dispatched = []
        self.targets = []
        self._real = ScanEngine()
    def run_tool(self, tool, target, args, timeout=1800.0):
        self.dispatched.append((tool, list(args)))
        self.targets.append(target)
        # return the real findings-bearing fixture for this tool
        try:
            return fx.load_fixture(tool, "finding")
        except Exception:
            return ""
    def _parse_tool_output(self, tool, raw_output, scan_id="", target=""):
        return self._real._parse_tool_output(tool, raw_output, scan_id, target)


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
    """Assemble the loop exactly as production does (minus real services).
    No attack_mapper injection: _parse_recon_output calls module-level
    map_finding_to_attack directly, same as legacy execute_scan."""
    mcp = ElianaMCPServer(scan_engine=engine,
                          memory=None)   # record goes through MemoryPort, not MCP here
    gate = GuardrailGate()
    return PlanningLoop(planner=planner, gate=gate, tools=mcp,
                        authorizer=authorizer, memory=memory, max_steps=12)


# --- the end-to-end test ---------------------------------------------------- #
def test_e2e_full_chain_gated_produces_real_findings():
    # LIVE-WIRING (Task 6.1): the loop now FORWARDS the gate-built ctx into
    # invoke, so the recon branch receives the real authorized target and the
    # real parser produces real findings. The gate still gates (sqlmap DENY),
    # the chain still connects, the one-time token still flows — the only change
    # from the Wave-1 honest-empty state is that findings are now REAL.
    planner = ScriptedPlanner([
        _invoke("nmap"),      # ALLOW -> real target -> 2 INFO findings (T1046)
        _invoke("sqlmap"),    # excluded -> gate DENY, no observation
        _invoke("sslscan"),   # ALLOW -> 1 MEDIUM finding (T1600); budget reached
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

    # --- the engine saw the AUTHORIZED, non-empty target (regression guard) - #
    assert engine.targets, "engine was never dispatched"
    assert all(t for t in engine.targets), "empty target reached the engine"
    # nmap + sslscan ran; sqlmap was DENYed and never dispatched
    dispatched_tools = [getattr(t, "value", t) for t, _ in engine.dispatched]
    assert dispatched_tools == ["nmap", "sslscan"], dispatched_tools

    # --- all three budget steps are present; the middle one is a DENY ------- #
    steps = outcome.trace.steps
    assert len(steps) == 3
    assert steps[0].gate.outcome == GateOutcome.ALLOW
    assert steps[0].decision.tool_call.tool_name == "nmap"
    assert steps[0].gate.token, "ALLOW step missing one-time token"
    assert steps[1].gate.outcome == GateOutcome.DENY          # sqlmap excluded
    assert steps[2].gate.outcome == GateOutcome.ALLOW
    assert outcome.stopped_reason == "step budget reached"

    # --- REAL findings now flow (not honest-empty, not fabricated): nmap's --
    # --- 2 INFO (T1046) + sslscan's 1 MEDIUM (T1600). Each carries an ATT&CK -
    # --- label and NO raw payload (projection honesty). --------------------- #
    assert len(outcome.findings) == 3, outcome.findings
    sevs = sorted(f["severity"] for f in outcome.findings)
    assert sevs == ["info", "info", "medium"], sevs
    for f in outcome.findings:
        assert f.get("attack_technique_id"), f
        assert "raw_output" not in f and "evidence" not in f


def test_e2e_planner_stop_after_real_work_records():
    """A planner-initiated STOP AFTER real assessment work is a normal
    completion -> it records experience (same _record_experience / tools_used as
    the other two exit paths). With ctx forwarding (Task 6.1), nmap runs (ALLOW
    + real findings), then the planner STOPs -> record fires because a tool ran
    and findings accumulated."""
    planner = ScriptedPlanner([
        _invoke("nmap"),
        PlannerDecision(kind=DecisionKind.STOP, rationale="assessment complete"),
    ])
    memory = RecordingMemory()
    engine = StubEngine()
    loop = _build_loop(planner, memory, StubAuthorizer(ok=True), engine)
    outcome = asyncio.run(loop.run(_goal()))
    # nmap ALLOW -> real target -> 2 INFO findings; next decision is STOP, which
    # is a normal completion that records (tool ran AND findings accumulated).
    assert outcome.stopped_reason == "assessment complete"
    assert len(outcome.findings) == 2
    assert all(f["severity"] == "info" for f in outcome.findings)
    assert memory.recorded is not None
    assert memory.recorded["tools_used"] == ["nmap"]
    assert len(memory.recorded["findings"]) == 2


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


class _EmptyOutputEngine(StubEngine):
    """Dispatches for real (target threaded) but the tool genuinely returns
    EMPTY output — exercises the honest-empty path AFTER ctx forwarding: the
    engine IS called with the authorized target, the real parser yields zero
    findings, and the loop stops on 'no further progress' WITHOUT fabricating."""
    def run_tool(self, tool, target, args, timeout=1800.0):
        self.dispatched.append((tool, list(args)))
        self.targets.append(target)
        return ""   # real empty output -> real parser -> zero findings


def test_e2e_honest_empty_on_genuinely_empty_tool_output():
    """With ctx forwarding (Task 6.1) the engine IS dispatched with the real
    target, but when a tool genuinely returns nothing the parser yields zero
    findings and the loop stops on 'no further progress' — honest-empty, never
    a fabricated placeholder. This is the safety-net that the root-cause bug
    (fabricated {'severity':'info'}) can never come back."""
    planner = ScriptedPlanner([_invoke("nmap"), _invoke("sslscan")])
    memory = RecordingMemory()
    engine = _EmptyOutputEngine()
    goal = AssessmentGoal(
        target_url="https://app.example.com",
        scope=ProgramScope(domains=["app.example.com"]),
        description="assess web_app attack surface", max_steps=2)
    loop = _build_loop(planner, memory, StubAuthorizer(ok=True), engine)
    outcome = asyncio.run(loop.run(goal))
    assert outcome.stopped_reason == "no further progress"
    assert len(outcome.trace.steps) == 1       # stopped after first ALLOW
    # the engine WAS called (ctx forwarded) with the authorized, non-empty target
    assert len(engine.dispatched) == 1
    assert engine.targets and all(t for t in engine.targets)
    # but zero findings (honest-empty), no fabrication
    assert outcome.findings == []
    # no-progress path records; tools_used counts the ALLOW step that produced
    # an (empty) observation, so it is ['nmap'] even though there were 0 findings
    assert memory.recorded is not None
    assert memory.recorded["tools_used"] == ["nmap"]
    assert memory.recorded["findings"] == []


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
