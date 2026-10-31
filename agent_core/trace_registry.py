"""trace_registry — an in-process, read-only publication point for the latest
DecisionTrace.

Why this exists: the PlanningLoop runs inside the telegram-runtime process,
while the dashboard runs in a separate process. There is intentionally NO
cross-process persistence in this wave (task 10) — that is future work. Within a
single process, the loop can publish its latest trace here and a read-only
dashboard view can read it. Across processes (the current production
deployment, where telegram and dashboard are separate systemd services), the
dashboard honestly sees nothing and reports "no agent trace available" rather
than faking data.

Read-only contract: the dashboard only ever calls `get_latest()`; it must never
mutate the trace or feed anything back into planning.
"""
from __future__ import annotations

from typing import Optional

from .models import DecisionTrace

# Module-level latest trace for THIS process only. None until a loop publishes.
_latest_trace: Optional[DecisionTrace] = None


def publish(trace: DecisionTrace) -> None:
    """Called by the PlanningLoop (or its caller) after a run to publish the
    latest trace for in-process read-only viewing."""
    global _latest_trace
    _latest_trace = trace


def get_latest() -> Optional[DecisionTrace]:
    """Read-only accessor for the dashboard. Returns the latest in-process trace,
    or None if no loop has run in this process (honest empty)."""
    return _latest_trace


def render_latest() -> dict:
    """Read-only render of the latest in-process trace into a plain dict for a
    dashboard view. Honest-empty (available=False) when no loop has run in this
    process — e.g. the production case where the dashboard is a separate process
    from the loop. Pure read: never mutates the trace or the registry, never
    feeds back into planning.

    Kept here (agent-agnostic, dependency-free) so it is unit-testable without
    importing the dashboard framework.
    """
    trace = _latest_trace
    if trace is None:
        return {"available": False,
                "reason": "no agent trace available",
                "steps": []}

    steps = []
    for s in getattr(trace, "steps", []):
        decision = getattr(s, "decision", None)
        gate = getattr(s, "gate", None)
        tool_call = getattr(decision, "tool_call", None) if decision else None
        gate_outcome = getattr(getattr(gate, "outcome", None), "value", None)
        steps.append({
            "index": getattr(s, "index", None),
            "tool": getattr(tool_call, "tool_name", None),
            "decision": getattr(getattr(decision, "kind", None), "value", None),
            "gate": gate_outcome,                       # "allow" / "deny"
            "gate_reason": getattr(gate, "reason", "") if gate else "",
            "rationale": getattr(decision, "rationale", "") if decision else "",
            "has_observation": getattr(s, "observation", None) is not None,
        })
    goal = getattr(trace, "goal", None)
    return {
        "available": True,
        "target": getattr(goal, "target_url", None) if goal else None,
        "steps": steps,
        "allow_count": sum(1 for s in steps if s["gate"] == "allow"),
        "deny_count": sum(1 for s in steps if s["gate"] == "deny"),
    }


def clear() -> None:
    """Reset the registry (used by tests to assert the honest-empty state)."""
    global _latest_trace
    _latest_trace = None
