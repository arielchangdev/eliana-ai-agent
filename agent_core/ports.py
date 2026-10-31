"""agent_core ports — the agent-agnostic interfaces the planning loop talks to.

These Protocols keep the core reusable: a future finance agent (Angelina) can
supply its own planner, tool server, memory, and authorization backend without
touching the loop or gate. There are deliberately NO Eliana-specific tool names
or constants here — Eliana-specific implementations live under agent_core/eliana/.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import (
    AssessmentGoal,
    GateDecision,
    Observation,
    PerceivedState,
    PlannerDecision,
    ToolCall,
    ToolSpec,
)


@runtime_checkable
class PlannerLLM(Protocol):
    """Wraps a reasoning model. Turns a perceived state into one next decision.

    Advisory only: the returned decision is NOT trusted until the GuardrailGate
    approves it. The planner never executes anything, never sees tool callables,
    never sees secrets."""

    async def decide(self, state: PerceivedState) -> PlannerDecision:
        """Return exactly one PlannerDecision (INVOKE_TOOL with a ToolCall, or
        STOP with a reason) for the given perceived state."""
        ...


@runtime_checkable
class ToolInvoker(Protocol):
    """Discovers and dispatches tools. The only component holding real tool
    references; the planner sees only the schemas returned by list_tools()."""

    def list_tools(self) -> list[ToolSpec]:
        """Return the discoverable tool schemas (names + input schemas)."""
        ...

    async def invoke(self, call: ToolCall, approval: GateDecision) -> Observation:
        """Dispatch ONLY if `approval` is an ALLOW issued for this exact call
        (server-side re-assertion / defense in depth). Otherwise refuse and run
        nothing."""
        ...


@runtime_checkable
class MemoryPort(Protocol):
    """Prior-experience hints that inform — but never control — planning.

    Hints may only reorder within the gate-permitted tool set; they can never
    introduce a tool the gate would reject."""

    def focus_hints(self, goal: AssessmentGoal) -> list[str]:
        """Recall methodology focus hints relevant to this goal (may be empty)."""
        ...

    def priority_tools(self, goal: AssessmentGoal) -> list[str]:
        """Recommend a priority ordering of tool names from prior efficacy
        (a reordering of permitted tools only; may be empty)."""
        ...

    def record(self, goal: AssessmentGoal, findings: list[dict],
               tools_used: list[str]) -> None:
        """Record this assessment's experience for future recall
        (methodology / efficacy only; attack-oriented content rejected)."""
        ...


@runtime_checkable
class AuthorizationPort(Protocol):
    """The explicit, non-expired authorization-record check. Wraps the real
    authorization store; the gate consults it and never reimplements it."""

    def is_authorized(self, target_url: str) -> bool:
        """True iff a valid (approved, non-expired) authorization record exists
        for this exact target."""
        ...
