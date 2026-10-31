"""LocalPlannerLLM — the on-box ($0) reasoning model behind the planning loop.

Implements the agent-agnostic `PlannerLLM` protocol. Calls the local Ollama
endpoint (the same 127.0.0.1:11434 that assessment_memory already uses); makes
NO paid cloud calls.

Default model = `llama3.2:3b`, bound per the design's "Planner model selection
(probe results)": vs llama3.1:8b it showed equal-or-better JSON format stability,
higher memory adherence (0%->100% sslscan selection with the hint, n=20), and
~2x speed. `llama3.1:latest` (8B) is kept as an optional higher-reasoning path
via the `model` parameter, not the default.

Guarantees:
  - returns exactly one PlannerDecision per call (INVOKE_TOOL + ToolCall, or STOP)
  - never returns tool callables; only a proposed tool *name* + args
  - fail-closed: if the endpoint is unreachable, raises PlannerUnavailable — it
    does NOT fabricate a decision and does NOT fall back to a cloud model. The
    loop maps this to stopped_reason="planner unavailable".
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Optional

from ..models import (
    DecisionKind,
    PerceivedState,
    PlannerDecision,
    ToolCall,
)

_DEFAULT_BASE_URL = "http://127.0.0.1:11434"
_DEFAULT_MODEL = "llama3.2:3b"   # probe-decided default (see design)

_SYSTEM_PROMPT = (
    "You are an authorized security ASSESSMENT planner. You pick the SINGLE next "
    "recon/enumeration tool to run, or decide to STOP. You never exploit. "
    "Respond ONLY with JSON of the form "
    '{"action": "invoke_tool"|"stop", "tool": "<one of the available tools>", '
    '"rationale": "<one sentence>"}. '
    "When action is \"stop\", omit tool or set it to null."
)


class PlannerUnavailable(RuntimeError):
    """Raised when the on-box planner endpoint is unreachable. The loop fails
    closed on this — it never fabricates a decision or calls a cloud model."""


class LocalPlannerLLM:
    """PlannerLLM implementation over a local Ollama chat endpoint."""

    def __init__(
        self,
        base_url: str = _DEFAULT_BASE_URL,
        model: str = _DEFAULT_MODEL,
        timeout: float = 120.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout

    # -- prompt construction -------------------------------------------- #
    def _build_user_prompt(self, state: PerceivedState) -> str:
        tool_names = [t.name for t in state.available_tools]
        lines = [
            f"Goal: {state.goal.description or 'assess the target attack surface'}.",
            f"Target: {state.goal.target_url}.",
            f"Available tools: {tool_names}.",
        ]
        if state.priority_tools:
            lines.append(f"Priority tools (from prior experience): "
                         f"{state.priority_tools}.")
        if state.memory_hints:
            lines.append("PRIOR EXPERIENCE HINTS: " + " ".join(state.memory_hints))
        if state.findings_so_far:
            # severity + ATT&CK label only; never raw payloads
            summary = [
                {"severity": f.get("severity"),
                 "attack_technique_id": f.get("attack_technique_id")}
                for f in state.findings_so_far
            ]
            lines.append(f"Findings so far: {summary}.")
        else:
            lines.append("Findings so far: none yet.")
        lines.append(f"Steps taken: {len(state.steps_taken)} "
                     f"(budget {state.goal.max_steps}).")
        lines.append("Pick the next tool, or STOP if the goal is met or no "
                     "further progress is possible.")
        return "\n".join(lines)

    # -- the one decision ------------------------------------------------ #
    async def decide(self, state: PerceivedState) -> PlannerDecision:
        """Return exactly one PlannerDecision. Raises PlannerUnavailable if the
        endpoint is unreachable (fail-closed)."""
        payload = {
            "model": self._model,
            "stream": False,
            "format": "json",
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": self._build_user_prompt(state)},
            ],
        }
        raw = self._chat(payload)              # may raise PlannerUnavailable
        return self._parse_decision(raw, state)

    # -- transport (sync urllib; the loop awaits via its own executor) --- #
    def _chat(self, payload: dict) -> str:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{self._base_url}/api/chat", data=data,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as r:
                body = json.loads(r.read())
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            # endpoint unreachable / timed out -> fail closed
            raise PlannerUnavailable(
                f"local planner endpoint unreachable: {exc}") from exc
        return str(body.get("message", {}).get("content", ""))

    # -- parse one decision from the model's JSON content ---------------- #
    def _parse_decision(self, content: str, state: PerceivedState) -> PlannerDecision:
        """Parse the model's JSON into exactly one PlannerDecision. A malformed
        or empty response is treated as a STOP (advisory, honest) rather than a
        fabricated tool call — the gate would reject a bad call anyway, but STOP
        keeps the loop honest and terminating."""
        try:
            obj = json.loads(content) if content.strip() else {}
        except (json.JSONDecodeError, ValueError):
            obj = {}

        action = str(obj.get("action", "")).strip().lower()
        tool = obj.get("tool")
        rationale = str(obj.get("rationale", "") or "")

        # Explicit stop, or no usable tool proposed -> STOP (advisory).
        if action == "stop" or not tool or not str(tool).strip():
            return PlannerDecision(
                kind=DecisionKind.STOP,
                tool_call=None,
                rationale=rationale or "planner proposed no tool",
            )

        # Propose a tool call. Arguments are intentionally empty here — the
        # planner never supplies flags; the gate forces _EVAL_MODE_ARGS.
        return PlannerDecision(
            kind=DecisionKind.INVOKE_TOOL,
            tool_call=ToolCall(tool_name=str(tool).strip().lower(), arguments={}),
            rationale=rationale,
        )
