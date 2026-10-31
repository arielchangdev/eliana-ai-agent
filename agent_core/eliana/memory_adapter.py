"""MemoryAdapter — the verifiable-learning seam, over the existing AssessmentMemory.

Implements the agent-agnostic `MemoryPort` by wrapping the existing
AssessmentMemory. It does NOT reimplement recall/record/ranking logic — it only
adapts the port's goal-oriented interface to AssessmentMemory's target_type
oriented methods, and clamps priority hints to the gate-permitted tool set.

Compliance preserved:
  - The underlying AssessmentMemory keeps its _ATTACK_ORIENTED_TERMS rejection
    (methodology/efficacy only); this adapter does not weaken it.
  - priority_tools() returns a REORDERING of permitted tool names only — it can
    never introduce a tool outside _AUTO_ORCHESTRATION_TOOLS (so a memory hint
    can never smuggle in sqlmap/an exploitation tool).

Signature notes (real code vs task wording):
  - AssessmentMemory has NO `record` method; the real method is
    `record_assessment(target, target_type, tools_used, findings, use_llm_summary)`.
    MemoryPort.record(goal, findings, tools_used) adapts onto it.
  - recall_focus_hints / recommend_priority_tools take a `target_type` string,
    not a goal — this adapter derives target_type from the goal.
"""
from __future__ import annotations

from typing import Optional

# Reuse the permitted-tool allowlist to clamp priority hints (never introduce a
# tool the gate would reject).
from app.bounty.scanner import _AUTO_ORCHESTRATION_TOOLS

from ..models import AssessmentGoal

_PERMITTED_TOOL_NAMES = frozenset(t.value for t in _AUTO_ORCHESTRATION_TOOLS)

# Default target type for recall/record when the goal doesn't specify one.
# Eliana's assessment memory keys experience by target type (e.g. "web_app").
_DEFAULT_TARGET_TYPE = "web_app"


class MemoryAdapter:
    """MemoryPort implementation wrapping AssessmentMemory. If no memory backend
    is supplied, all methods degrade gracefully (empty hints / no-op record)."""

    def __init__(self, memory: Optional[object] = None,
                 target_type: str = _DEFAULT_TARGET_TYPE) -> None:
        self._memory = memory
        self._target_type = target_type

    # -- helpers --------------------------------------------------------- #
    def _goal_target_type(self, goal: AssessmentGoal) -> str:
        """Derive the memory target_type for a goal. Kept simple and explicit:
        use the configured default unless the goal description names a known
        type. (AssessmentMemory keys by target_type string.)"""
        desc = (goal.description or "").lower()
        for t in ("web_app", "network_service", "database_endpoint"):
            if t in desc or t.replace("_", " ") in desc:
                return t
        return self._target_type

    # -- MemoryPort: recall focus hints ---------------------------------- #
    def focus_hints(self, goal: AssessmentGoal) -> list[str]:
        if self._memory is None:
            return []
        try:
            return list(self._memory.recall_focus_hints(
                self._goal_target_type(goal),
                query=goal.description or goal.target_url))
        except Exception:  # noqa: BLE001 - memory is advisory; never break planning
            return []

    # -- MemoryPort: priority tools (clamped to permitted set) ----------- #
    def priority_tools(self, goal: AssessmentGoal) -> list[str]:
        """Return a priority ordering of tool NAMES, filtered to the
        gate-permitted allowlist. This guarantees a memory hint can only
        *reorder within* permitted tools, never introduce a new one."""
        if self._memory is None:
            return []
        try:
            raw = self._memory.recommend_priority_tools(
                self._goal_target_type(goal),
                query=goal.description or goal.target_url)
        except Exception:  # noqa: BLE001
            return []
        # clamp: keep only permitted tool names, preserve recommended order,
        # drop duplicates
        seen: set[str] = set()
        clamped: list[str] = []
        for name in raw or []:
            n = str(name).strip().lower()
            if n in _PERMITTED_TOOL_NAMES and n not in seen:
                seen.add(n)
                clamped.append(n)
        return clamped

    # -- MemoryPort: record experience ----------------------------------- #
    def record(self, goal: AssessmentGoal, findings: list[dict],
               tools_used: list[str]) -> None:
        """Record methodology experience. Adapts onto AssessmentMemory's
        record_assessment(target, target_type, tools_used, findings). The
        underlying layer applies its _ATTACK_ORIENTED_TERMS rejection; this
        adapter does not bypass or weaken it."""
        if self._memory is None:
            return
        try:
            self._memory.record_assessment(
                target=goal.target_url,
                target_type=self._goal_target_type(goal),
                tools_used=list(tools_used or []),
                findings=list(findings or []),
            )
        except Exception:  # noqa: BLE001 - recording failure must not break the loop
            pass
