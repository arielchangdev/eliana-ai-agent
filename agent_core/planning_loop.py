"""PlanningLoop — the perceive → decide → act → observe → reflect cycle.

Agent-agnostic: holds NO tool references. It talks only to the injected
interfaces — `PlannerLLM`, `GuardrailGate`, `ToolInvoker` (MCP-backed),
`MemoryPort`, and an `AuthorizationPort` (for the gate context). All autonomy
funnels through `GuardrailGate.check`; the only path to a tool is an ALLOW +
token handed to `ToolInvoker.invoke`.

Loop invariants enforced here (design):
  - Gate invariant   : no Observation is produced for a call that was not
    ALLOWed — executed_calls ⊆ allowed_calls.
  - Progress invariant: each iteration consumes one step of the budget or sets a
    stop condition; the loop always terminates within goal.max_steps.
  - Honesty invariant : findings only grow with findings actually returned by a
    tool via an ALLOWed invoke — the planner cannot inject findings (its
    rationale is recorded, but only observation.findings are appended).

Fail-closed: if the planner is unavailable, the loop stops with
stopped_reason="planner unavailable" and NEVER falls back to an ungated or raw
tool path.
"""
from __future__ import annotations

from typing import Optional

from .models import (
    AssessmentGoal,
    AssessmentOutcome,
    DecisionKind,
    DecisionTrace,
    GateContext,
    GateDecision,
    GateOutcome,
    PerceivedState,
    PlannerDecision,
    StepRecord,
    ToolCall,
)

# Fail-closed sentinel reason when the on-box planner is unreachable.
PLANNER_UNAVAILABLE_REASON = "planner unavailable"


def _noop_allow_placeholder(call: Optional[ToolCall]) -> GateDecision:
    """A neutral gate decision used only to fill the StepRecord of a STOP step
    (no tool runs on STOP). It is NOT an ALLOW with a token — it carries no
    token and a benign DENY-neutral outcome so it can never be mistaken for an
    executable approval."""
    placeholder = call or ToolCall(tool_name="stop")
    return GateDecision(outcome=GateOutcome.DENY, call=placeholder,
                        reason="stop (no tool)", token="")


class PlanningLoop:
    """Drives the assessment loop. Owns no tool references."""

    def __init__(
        self,
        planner,                 # PlannerLLM
        gate,                    # GuardrailGate
        tools,                   # ToolInvoker (MCP server)
        authorizer,              # AuthorizationPort (for GateContext)
        memory=None,             # MemoryPort (optional)
        max_steps: int = 12,
    ) -> None:
        self._planner = planner
        self._gate = gate
        self._tools = tools
        self._authorizer = authorizer
        self._memory = memory
        self._max_steps = max_steps

    # -- reflect helper -------------------------------------------------- #
    @staticmethod
    def _no_new_information(observation) -> bool:
        """Stop condition: an observation that yielded no findings is treated as
        'no further progress' for that step's tool. Conservative and simple —
        keeps the loop terminating and honest."""
        return not getattr(observation, "findings", None)

    # -- the loop -------------------------------------------------------- #
    async def run(self, goal: AssessmentGoal) -> AssessmentOutcome:
        """Execute perceive→decide→gate→act→observe→reflect until the goal is
        met, no progress is made, the planner is unavailable, or the step budget
        (min(goal.max_steps, self._max_steps)) is exhausted."""
        trace = DecisionTrace(goal=goal)
        findings: list[dict] = []
        ctx = GateContext(target_url=goal.target_url, scope=goal.scope,
                          authorizer=self._authorizer)

        # progress invariant: hard cap on iterations = the step budget
        budget = min(goal.max_steps, self._max_steps)

        for step_index in range(budget):
            # ---- PERCEIVE ----
            hints = self._memory.focus_hints(goal) if self._memory else []
            priority = self._memory.priority_tools(goal) if self._memory else []
            state = PerceivedState(
                goal=goal,
                findings_so_far=list(findings),
                steps_taken=list(trace.steps),
                available_tools=self._tools.list_tools(),
                memory_hints=hints,
                priority_tools=priority,
            )

            # ---- DECIDE (advisory only; fail-closed on unavailability) ----
            try:
                decision = await self._planner.decide(state)
            except Exception as exc:  # noqa: BLE001
                # Planner unavailable (e.g. PlannerUnavailable) -> FAIL CLOSED.
                # Never fall back to an ungated or raw tool path.
                if _is_planner_unavailable(exc):
                    return AssessmentOutcome(
                        findings=findings, trace=trace,
                        stopped_reason=PLANNER_UNAVAILABLE_REASON)
                raise

            if decision.kind == DecisionKind.STOP:
                trace.append(StepRecord(
                    index=step_index, decision=decision,
                    gate=_noop_allow_placeholder(decision.tool_call),
                    observation=None))
                return AssessmentOutcome(
                    findings=findings, trace=trace,
                    stopped_reason=decision.rationale or "planner stop")

            # ---- GATE (the leash — non-bypassable) ----
            call = decision.tool_call
            gate_decision = self._gate.check(call, ctx)
            if gate_decision.outcome == GateOutcome.DENY:
                # refusal is DATA: record it, produce NO observation, and let the
                # planner re-plan WITHOUT this option on the next iteration.
                trace.append(StepRecord(
                    index=step_index, decision=decision,
                    gate=gate_decision, observation=None))
                continue

            # ---- ACT + OBSERVE (only ALLOW + token reaches the server) ----
            observation = await self._tools.invoke(gate_decision.call, gate_decision)
            # HONESTY invariant: only tool-returned findings are appended; the
            # planner's decision/rationale can never add a finding.
            tool_findings = list(getattr(observation, "findings", []) or [])
            findings.extend(tool_findings)
            trace.append(StepRecord(
                index=step_index, decision=decision,
                gate=gate_decision, observation=observation))

            # ---- REFLECT ----
            if self._no_new_information(observation):
                self._record_experience(goal, findings, trace)
                return AssessmentOutcome(
                    findings=findings, trace=trace,
                    stopped_reason="no further progress")

        # ---- CLOSE THE LEARNING LOOP (verifiable growth) ----
        self._record_experience(goal, findings, trace)
        return AssessmentOutcome(
            findings=findings, trace=trace, stopped_reason="step budget reached")

    # -- record experience on normal completion -------------------------- #
    def _record_experience(self, goal, findings, trace) -> None:
        if self._memory is None:
            return
        try:
            self._memory.record(goal, findings, tools_used=_tools_used(trace))
        except Exception:  # noqa: BLE001 - recording must not break the loop
            pass


def _tools_used(trace: DecisionTrace) -> list[str]:
    """Tool names of steps that actually produced an observation (i.e. ran)."""
    used: list[str] = []
    for step in trace.steps:
        if step.observation is not None:
            name = getattr(step.gate.call, "tool_name", None)
            if name and name not in used:
                used.append(name)
    return used


def _is_planner_unavailable(exc: Exception) -> bool:
    """Detect the planner-unavailable signal without importing the Eliana-
    specific exception into the agent-agnostic core. Matches by class name so
    any PlannerLLM implementation can raise its own 'unavailable' type."""
    for klass in type(exc).__mro__:
        if klass.__name__ == "PlannerUnavailable":
            return True
    return False
