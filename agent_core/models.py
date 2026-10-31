"""agent_core data models — frozen dataclasses / enums for the planning loop.

Agent-agnostic: no Eliana-specific tool names or constants here. `ProgramScope`
is reused from the existing Eliana models by import (not redefined), per the
eliana-agent-core design — it is the shared scope shape the gate already uses.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# Reuse the existing scope type — do NOT redefine it. The GuardrailGate's
# is_target_in_scope check operates on this exact structure.
from app.bounty.models import ProgramScope


# --------------------------------------------------------------------------- #
# Tool schema (what the planner may discover — names + schema, never callables)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ToolSpec:
    """A discoverable tool: its name, human description, and JSON input schema.

    The planner sees only this (never the real callable), so it cannot smuggle
    in an unlisted tool."""
    name: str
    description: str
    input_schema: dict = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# What the planner is allowed to see about the world
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class AssessmentGoal:
    target_url: str
    scope: ProgramScope                   # reused from app.bounty.models
    description: str = ""                 # e.g. "assess web_app attack surface"
    max_steps: int = 12

    def __post_init__(self) -> None:
        if self.max_steps < 1:
            raise ValueError("AssessmentGoal.max_steps must be >= 1")


@dataclass(frozen=True)
class PerceivedState:
    goal: "AssessmentGoal"
    findings_so_far: list[dict]           # severity + ATT&CK label only
    steps_taken: list["StepRecord"]
    available_tools: list["ToolSpec"]     # names + schemas, NOT callables
    memory_hints: list[str] = field(default_factory=list)      # recall_focus_hints
    priority_tools: list[str] = field(default_factory=list)    # recommend_priority_tools


# --------------------------------------------------------------------------- #
# The planner's single decision per turn
# --------------------------------------------------------------------------- #
class DecisionKind(Enum):
    INVOKE_TOOL = "invoke_tool"
    STOP = "stop"


@dataclass(frozen=True)
class ToolCall:
    tool_name: str
    arguments: dict = field(default_factory=dict)   # proposed; gate may override

    def __post_init__(self) -> None:
        if not isinstance(self.tool_name, str) or not self.tool_name.strip():
            raise ValueError("ToolCall.tool_name must be a non-empty string")


@dataclass(frozen=True)
class PlannerDecision:
    kind: DecisionKind
    tool_call: Optional["ToolCall"] = None
    rationale: str = ""                   # recorded in the trace for honesty


# --------------------------------------------------------------------------- #
# The gate's verdict
# --------------------------------------------------------------------------- #
class GateOutcome(Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class GateDecision:
    outcome: GateOutcome
    call: "ToolCall"                      # with normalized eval-mode args if ALLOW
    reason: str = ""
    token: str = ""                       # one-time approval token for this exact call


@dataclass(frozen=True)
class GateContext:
    target_url: str
    scope: ProgramScope
    authorizer: "object"                  # AuthorizationPort (ports.py); avoids import cycle


# --------------------------------------------------------------------------- #
# Observations + verifiable trace
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Observation:
    tool_name: str
    findings: list[dict]
    raw_excerpt: str = ""


@dataclass(frozen=True)
class StepRecord:
    index: int
    decision: PlannerDecision
    gate: GateDecision
    observation: Optional[Observation] = None


@dataclass
class DecisionTrace:
    goal: AssessmentGoal
    steps: list[StepRecord] = field(default_factory=list)

    def append(self, step: StepRecord) -> None:
        self.steps.append(step)


@dataclass(frozen=True)
class AssessmentOutcome:
    findings: list[dict]
    trace: DecisionTrace
    stopped_reason: str = ""
