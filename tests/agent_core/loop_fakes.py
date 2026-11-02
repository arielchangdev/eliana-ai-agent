"""Shared scripted fakes for PlanningLoop tests (tasks 8.2 / 8.3 / 8.4).

All dependencies are faked/scripted — no real Ollama, no Kali, no real scans.
These fakes let the tests drive adversarial and honest scenarios through the
loop and assert the gate / progress / honesty invariants.
"""
from __future__ import annotations

from agent_core.models import (
    DecisionKind,
    GateDecision,
    GateOutcome,
    Observation,
    PlannerDecision,
    ToolCall,
    ToolSpec,
)
from app.bounty.models import ProgramScope


class PlannerUnavailable(RuntimeError):
    """Mirror of the planner's unavailable signal (matched by class name in the
    loop's fail-closed detection)."""


def scope() -> ProgramScope:
    return ProgramScope(domains=["app.example.com"])


class ScriptedPlanner:
    """Returns a pre-scripted sequence of PlannerDecisions; STOP when exhausted.
    Records how many times decide() was called (invocation count for P6)."""

    def __init__(self, decisions=None, stop_when_done=True):
        self._decisions = list(decisions or [])
        self._stop_when_done = stop_when_done
        self.decide_calls = 0

    async def decide(self, state):
        self.decide_calls += 1
        if self._decisions:
            return self._decisions.pop(0)
        if self._stop_when_done:
            return PlannerDecision(kind=DecisionKind.STOP, rationale="exhausted")
        # adversarial: never stops on its own — keep proposing a tool forever
        return PlannerDecision(
            kind=DecisionKind.INVOKE_TOOL,
            tool_call=ToolCall(tool_name="nmap", arguments={}),
            rationale="never-stop")


class DeadPlanner:
    """Always raises PlannerUnavailable (fail-closed scenario)."""
    def __init__(self):
        self.decide_calls = 0

    async def decide(self, state):
        self.decide_calls += 1
        raise PlannerUnavailable("endpoint down")


class FakeGate:
    """Scriptable gate. mode:
      - 'allow' : ALLOW every call (normalized args emptied, fresh token)
      - 'deny'  : DENY every call
      - callable: fn(call, ctx) -> bool deciding ALLOW
    Records all checks for invariant assertions."""

    def __init__(self, mode="allow"):
        self._mode = mode
        self.checks = []
        self._n = 0

    def check(self, call, ctx):
        self._n += 1
        self.checks.append(call)
        allow = (self._mode == "allow") if isinstance(self._mode, str) else bool(self._mode(call, ctx))
        if self._mode == "deny":
            allow = False
        if allow:
            return GateDecision(
                outcome=GateOutcome.ALLOW,
                call=ToolCall(tool_name=call.tool_name, arguments={}),
                token=f"tok-{self._n}")
        return GateDecision(outcome=GateOutcome.DENY, call=call,
                            reason="denied by fake gate")


class FakeTools:
    """MCP-server stand-in. Returns a canned Observation per invoke; records how
    many times invoke() ran and which tokens it saw (to assert ALLOW-only)."""

    def __init__(self, findings_per_call=None, tool_specs=None):
        self._findings = findings_per_call if findings_per_call is not None else [
            {"severity": "info", "attack_technique_id": "T1046"}]
        self._specs = tool_specs or [ToolSpec("recon_scan", "recon")]
        self.invoke_calls = 0
        self.seen_tokens = []
        self.seen_ctx = []   # GateContext objects the loop forwarded (Task 6.1)

    def list_tools(self):
        return list(self._specs)

    async def invoke(self, call, approval, ctx=None):
        # ctx is the optional GateContext the loop now forwards (live-wiring
        # Task 6.1). This fake ignores the real target (it returns canned
        # findings), but records that a ctx was threaded so the loop-forwarding
        # assertion can verify it.
        self.invoke_calls += 1
        self.seen_tokens.append(getattr(approval, "token", None))
        self.seen_ctx.append(ctx)
        return Observation(tool_name=call.tool_name,
                           findings=[dict(f) for f in self._findings])


class EmptyTools(FakeTools):
    """Invoke returns NO findings (drives the no-new-information stop)."""
    def __init__(self, tool_specs=None):
        super().__init__(findings_per_call=[], tool_specs=tool_specs)


class StubAuthorizer:
    def __init__(self, ok=True):
        self._ok = ok
    def is_authorized(self, target_url):
        return self._ok


class RecordingMemory:
    """MemoryPort stand-in; records whether record() was called."""
    def __init__(self):
        self.recorded = None
    def focus_hints(self, goal):
        return []
    def priority_tools(self, goal):
        return []
    def record(self, goal, findings, tools_used):
        self.recorded = {"findings": list(findings), "tools_used": list(tools_used)}
