"""GuardrailGate — the single, non-bypassable enforcement point.

This is the existing Eliana dual gate + eval-mode allowlist **relocated, not
reinvented**. It imports and reuses the real functions so the subset / leash
guarantee (design Property 2) is *proven*, not rewritten:

- scope check     -> app.bounty.scanner.is_target_in_scope   (reused verbatim)
- tool allowlist  -> app.bounty.scanner._AUTO_ORCHESTRATION_TOOLS (excludes sqlmap)
- argument allowlist -> app.bounty.scanner._EVAL_MODE_ARGS    (forced, never merged)
- authorization   -> injected AuthorizationPort wrapping AuthorizedScanner.is_authorized

Because the gate consults the *same* functions the pre-agent path used, the set
of ALLOW-able calls cannot be larger than what the old code permitted.

Note on tool resolution: there is no `_resolve_scan_tool` in scanner.py. The
real codebase resolves names via `ScanTool(name.lower())` (see crawler.py), so
this module provides a small `_resolve_scan_tool` helper using that exact
pattern — name resolution only, no rule logic duplicated.
"""
from __future__ import annotations

import secrets
from typing import Callable, Optional

# Reuse existing logic — do NOT reimplement. These are the single sources of truth.
from app.bounty.scanner import (
    is_target_in_scope,
    _AUTO_ORCHESTRATION_TOOLS,
    _EVAL_MODE_ARGS,
)
from app.bounty.enums import ScanTool

from .models import (
    GateContext,
    GateDecision,
    GateOutcome,
    ToolCall,
)


def _resolve_scan_tool(name: str) -> Optional[ScanTool]:
    """Resolve a tool name string to a ScanTool enum, or None if unknown.

    Mirrors the existing resolution pattern in crawler.py
    (`ScanTool(str(name).lower())` guarded by ValueError/KeyError). Pure name
    resolution — no allowlist/scope/authorization rules are duplicated here."""
    if not isinstance(name, str):
        return None
    try:
        return ScanTool(name.strip().lower())
    except (ValueError, KeyError):
        return None


class GuardrailGate:
    """Synchronous, deterministic enforcement. ALLOW only when all four
    postconditions pass; every decision (allow or deny) appends one audit record.

    audit_sink: optional callable(record: dict) -> None. Receives one dict per
    decision so a DecisionTrace / dashboard can show exactly what was gated.
    """

    def __init__(self, audit_sink: Optional[Callable[[dict], None]] = None) -> None:
        self._audit_sink = audit_sink

    # -- audit ----------------------------------------------------------- #
    def _audit(self, outcome: str, call: ToolCall, reason: str = "") -> None:
        if self._audit_sink is None:
            return
        try:
            self._audit_sink({
                "outcome": outcome,
                "tool_name": call.tool_name,
                "arguments": call.arguments,
                "reason": reason,
            })
        except Exception:  # noqa: BLE001 - audit must never break the gate
            pass

    def _deny(self, call: ToolCall, reason: str) -> GateDecision:
        self._audit("deny", call, reason)
        return GateDecision(outcome=GateOutcome.DENY, call=call, reason=reason)

    @staticmethod
    def _issue_token() -> str:
        """One-time approval token, bound to this exact (normalized) call by the
        caller/server which stores it alongside the decision."""
        return secrets.token_urlsafe(24)

    # -- the gate -------------------------------------------------------- #
    def check(self, call: ToolCall, ctx: GateContext) -> GateDecision:
        """Return ALLOW (with normalized eval-mode args + one-time token) or
        DENY(reason). Deterministic; side-effect-free except one audit record.

        Four postconditions (all must pass for ALLOW; any failure => DENY), in
        order:
          1. tool resolves to a ScanTool in _AUTO_ORCHESTRATION_TOOLS
             (so sqlmap / exploitation / unknown tools => DENY)
          2. is_target_in_scope(ctx.target_url, ctx.scope) is True
          3. ctx.authorizer.is_authorized(ctx.target_url) is True
          4. arguments FORCED to _EVAL_MODE_ARGS[tool] (planner args discarded,
             never merged)
        """
        # 1. tool must be an auto-orchestration (assessment) tool
        tool = _resolve_scan_tool(call.tool_name)
        if tool is None or tool not in _AUTO_ORCHESTRATION_TOOLS:
            return self._deny(
                call, f"tool not permitted for autonomous use: {call.tool_name}")

        # 2. scope (reused pure function; parses the URL itself)
        if not is_target_in_scope(ctx.target_url, ctx.scope):
            return self._deny(call, f"target not in scope: {ctx.target_url}")

        # 3. explicit, non-expired human authorization record (reused via port)
        if not ctx.authorizer.is_authorized(ctx.target_url):
            return self._deny(call, f"no valid authorization for: {ctx.target_url}")

        # 4. arguments are FORCED to the eval-mode allowlist — planner-supplied
        #    flags are discarded and replaced, never merged.
        normalized = ToolCall(
            tool_name=call.tool_name,
            arguments=list(_EVAL_MODE_ARGS.get(tool, [])),
        )
        token = self._issue_token()
        self._audit("allow", normalized)
        return GateDecision(
            outcome=GateOutcome.ALLOW, call=normalized, reason="", token=token)
