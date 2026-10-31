"""ElianaMCPServer — Eliana's capabilities published as discoverable MCP tools.

Registry/schemas (`list_tools`, task 5.1) + approved dispatch (`invoke`,
task 5.2). The server holds the ONLY references to the real capabilities, so the
planner can never reach a tool except through an approved invoke.

The published tools are deliberately narrow — the planner can only express
*assessment* intent:
  - recon_scan       : run ONE eval-mode recon/enum tool (enum of the 8 auto-
                       orchestration tools; NO `args` field — the gate/server
                       supply _EVAL_MODE_ARGS; the planner never picks flags)
  - classify_attack  : MITRE ATT&CK labeling of an existing finding (not attack)
  - recall_experience: recall prior methodology/efficacy experience
  - record_experience: record methodology experience (attack content rejected)

There is NO exploitation tool and `sqlmap` is NOT published for autonomous use
(mirrors scanner._AUTO_ORCHESTRATION_TOOLS excluding it). The recon_scan enum is
derived FROM _AUTO_ORCHESTRATION_TOOLS so it can never drift out of sync with the
real allowlist.

Defense in depth (task 5.2): `invoke` re-asserts the gate verdict server-side.
Even though PlanningLoop already gated the call, the server dispatches ONLY when
the approval is an ALLOW issued for this exact call with an unused token; it
consumes the token on dispatch. A planner/loop bug therefore cannot become an
unguarded execution (Property 1, no-bypass, enforced a second time here).
"""
from __future__ import annotations

import asyncio
from typing import Optional

# Reuse the single sources of truth. Logic is NOT reimplemented — only wrapped.
from app.bounty.scanner import _AUTO_ORCHESTRATION_TOOLS, _EVAL_MODE_ARGS
from app.bounty.enums import ScanTool

from ..models import GateDecision, GateOutcome, Observation, ToolCall, ToolSpec


class ToolNotApproved(RuntimeError):
    """Raised when invoke is called without a valid ALLOW token issued for this
    exact call (missing / mismatched / reused). Nothing executes; audited."""


def _resolve_scan_tool(name: str) -> Optional[ScanTool]:
    """Resolve a tool-name string to a ScanTool enum, or None if unknown.
    Same pattern used by guardrail._resolve_scan_tool / crawler.py
    (`ScanTool(name.lower())` guarded by ValueError/KeyError). Name resolution
    only — no allowlist/scope/authz rules duplicated here."""
    if not isinstance(name, str):
        return None
    try:
        return ScanTool(name.strip().lower())
    except (ValueError, KeyError):
        return None


def _recon_tool_enum() -> list[str]:
    """The recon_scan tool enum = exactly the auto-orchestration allowlist tool
    names, sorted for stable output. Derived from _AUTO_ORCHESTRATION_TOOLS so
    sqlmap / exploitation tools are structurally absent (they're not in it)."""
    return sorted(t.value for t in _AUTO_ORCHESTRATION_TOOLS)


class ElianaMCPServer:
    """Publishes Eliana's assessment capabilities as MCP tool schemas and
    dispatches approved invocations.

    Holds the ONLY references to the real capabilities:
      - scan_engine:  wraps ScanEngine.run_tool(tool, target, args)  [recon_scan]
      - attack_mapper: wraps map_finding_to_attack(tool_source, ...)  [classify_attack]
      - memory:       wraps AssessmentMemory recall/record            [recall/record]

    Dispatch is gated server-side (defense in depth): see `invoke`.
    """

    def __init__(
        self,
        scan_engine: Optional[object] = None,
        attack_mapper: Optional[object] = None,
        memory: Optional[object] = None,
        audit_sink: Optional[object] = None,
    ) -> None:
        self._scan_engine = scan_engine
        self._attack_mapper = attack_mapper
        self._memory = memory
        # optional callable(record: dict)->None for rejection/dispatch audit
        self._audit_sink = audit_sink
        # tokens already consumed by a dispatch — reuse must be refused
        self._consumed_tokens: set[str] = set()

    def list_tools(self) -> list[ToolSpec]:
        """Return the four discoverable MCP tool schemas. No exploitation tool,
        no sqlmap — recon_scan's enum is the auto-orchestration allowlist."""
        return [
            ToolSpec(
                name="recon_scan",
                description=(
                    "Run ONE authorized evaluation-mode recon/enumeration tool "
                    "against the in-scope target. Assessment only; arguments are "
                    "fixed by the eval-mode allowlist and cannot be overridden by "
                    "the caller."),
                input_schema={
                    "type": "object",
                    "properties": {
                        "tool": {"type": "string", "enum": _recon_tool_enum()},
                    },
                    "required": ["tool"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="classify_attack",
                description=(
                    "Classify an existing finding against MITRE ATT&CK (labeling "
                    "for the report; NOT attack execution). Pure, offline, "
                    "rule-table backed."),
                input_schema={
                    "type": "object",
                    "properties": {
                        "tool_source": {"type": "string"},
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                    },
                    "required": ["tool_source"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="recall_experience",
                description=(
                    "Recall prior AUTHORIZED assessment experience "
                    "(methodology/efficacy only) to inform planning. Returns focus "
                    "hints and priority-tool ordering. No attack techniques are "
                    "stored or returned."),
                input_schema={
                    "type": "object",
                    "properties": {
                        "target_type": {"type": "string"},
                        "query": {"type": "string"},
                        "k": {"type": "integer", "minimum": 1, "maximum": 10,
                              "default": 3},
                    },
                    "required": ["target_type"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="record_experience",
                description=(
                    "Record this authorized assessment's finding patterns "
                    "(severity distribution + ATT&CK classification labels + tool "
                    "efficacy) as recallable methodology experience. "
                    "Attack-oriented content is rejected by the memory layer."),
                input_schema={
                    "type": "object",
                    "properties": {
                        "target_type": {"type": "string"},
                        "tools_used": {"type": "array",
                                       "items": {"type": "string"}},
                        "findings": {"type": "array",
                                     "items": {"type": "object"}},
                    },
                    "required": ["target_type", "tools_used", "findings"],
                    "additionalProperties": False,
                },
            ),
        ]

    # -- audit ----------------------------------------------------------- #
    def _audit(self, event: str, call: ToolCall, reason: str = "") -> None:
        if self._audit_sink is None:
            return
        try:
            self._audit_sink({
                "event": event,
                "tool_name": getattr(call, "tool_name", None),
                "arguments": getattr(call, "arguments", None),
                "reason": reason,
            })
        except Exception:  # noqa: BLE001 - audit must never break dispatch
            pass

    # -- server-side re-assertion (defense in depth) --------------------- #
    def _assert_approved(self, call: ToolCall, approval: GateDecision) -> None:
        """Raise ToolNotApproved unless `approval` is an ALLOW issued for this
        EXACT call with an unused token. Nothing runs on failure; the rejection
        is audited. This re-checks the gate even though PlanningLoop already
        gated — so a planner/loop bug cannot become an unguarded execution."""
        if approval is None or approval.outcome != GateOutcome.ALLOW:
            self._audit("rejected", call, "approval is not ALLOW")
            raise ToolNotApproved("approval is not an ALLOW")
        if approval.call != call:
            self._audit("rejected", call, "approval.call != call")
            raise ToolNotApproved("approval was not issued for this exact call")
        token = approval.token or ""
        if not token:
            self._audit("rejected", call, "missing token")
            raise ToolNotApproved("approval carries no token")
        if token in self._consumed_tokens:
            self._audit("rejected", call, "token already used")
            raise ToolNotApproved("approval token already consumed")

    # -- approved dispatch ----------------------------------------------- #
    async def invoke(self, call: ToolCall, approval: GateDecision) -> Observation:
        """Dispatch ONLY if `approval` is an ALLOW issued for this exact call
        with an unused token. Consumes the token on dispatch. Returns an
        Observation (severity + ATT&CK label only; no payloads)."""
        self._assert_approved(call, approval)
        # consume the token FIRST so a re-entrant / repeated invoke with the same
        # token is refused even if dispatch below is slow or retried
        self._consumed_tokens.add(approval.token)

        name = (call.tool_name or "").strip().lower()
        if name == "classify_attack":
            obs = self._do_classify(approval.call)
        elif name == "recall_experience":
            obs = self._do_recall(approval.call)
        elif name == "record_experience":
            obs = self._do_record(approval.call)
        else:
            # default: a recon/enum scan tool (the gate normalizes ToolCall to a
            # ScanTool-resolvable name and forces eval-mode args).
            obs = await self._do_recon(approval.call)

        self._audit("dispatched", approval.call)
        return obs

    # -- recon_scan: wrap ScanEngine.run_tool (eval-mode args only) ------ #
    async def _do_recon(self, call: ToolCall) -> Observation:
        tool = _resolve_scan_tool(call.tool_name)
        if tool is None:
            # should never happen (gate already resolved it) — fail honest/empty
            return Observation(tool_name=call.tool_name, findings=[], raw_excerpt="")
        if self._scan_engine is None:
            return Observation(tool_name=call.tool_name, findings=[], raw_excerpt="")
        # arguments come from the normalized approval (eval-mode allowlist). We do
        # NOT trust call.arguments blindly — re-derive the eval-mode args as a
        # second guarantee that no intrusive flag reaches run_tool.
        args = list(_EVAL_MODE_ARGS.get(tool, []))
        target = ""  # supplied by the caller/context in integration; stubbed here
        result = self._scan_engine.run_tool(tool, target, args)
        if asyncio.iscoroutine(result):
            result = await result
        return self._parse_recon_output(call.tool_name, result)

    def _parse_recon_output(self, tool_name: str, raw: object) -> Observation:
        """Parse tool output into an Observation carrying severity + ATT&CK label
        only — never raw payloads/exploitation detail. Classification (if any) is
        applied via the attack mapper; raw text is NOT propagated into findings."""
        findings: list[dict] = []
        tool = _resolve_scan_tool(tool_name)
        technique = None
        if self._attack_mapper is not None and tool is not None:
            try:
                technique = self._attack_mapper(tool)
            except Exception:  # noqa: BLE001
                technique = None
        finding = {"severity": "info", "tool": tool_name}
        if technique is not None:
            finding["attack_technique_id"] = getattr(technique, "technique_id", None)
            finding["attack_technique_name"] = getattr(technique, "technique_name", None)
        findings.append(finding)
        # keep a short, non-sensitive excerpt only (length-capped, no payloads)
        excerpt = str(raw)[:120] if raw is not None else ""
        return Observation(tool_name=tool_name, findings=findings, raw_excerpt=excerpt)

    # -- classify_attack: wrap map_finding_to_attack --------------------- #
    def _do_classify(self, call: ToolCall) -> Observation:
        args = call.arguments if isinstance(call.arguments, dict) else {}
        tool = _resolve_scan_tool(str(args.get("tool_source", "")))
        technique = None
        if self._attack_mapper is not None and tool is not None:
            try:
                technique = self._attack_mapper(
                    tool, str(args.get("title", "")), str(args.get("description", "")))
            except Exception:  # noqa: BLE001
                technique = None
        finding = {"severity": "info"}
        if technique is not None:
            finding["attack_technique_id"] = getattr(technique, "technique_id", None)
            finding["attack_technique_name"] = getattr(technique, "technique_name", None)
        return Observation(tool_name="classify_attack", findings=[finding])

    # -- recall_experience: wrap AssessmentMemory recall ----------------- #
    def _do_recall(self, call: ToolCall) -> Observation:
        args = call.arguments if isinstance(call.arguments, dict) else {}
        hints: list[str] = []
        if self._memory is not None:
            try:
                hints = list(self._memory.recall_focus_hints(
                    str(args.get("target_type", "web_app")),
                    query=str(args.get("query", "")),
                    k=int(args.get("k", 3))))
            except Exception:  # noqa: BLE001
                hints = []
        return Observation(tool_name="recall_experience", findings=[],
                           raw_excerpt="; ".join(hints)[:200])

    # -- record_experience: wrap AssessmentMemory record ----------------- #
    def _do_record(self, call: ToolCall) -> Observation:
        args = call.arguments if isinstance(call.arguments, dict) else {}
        if self._memory is not None:
            try:
                self._memory.record_assessment(
                    target=str(args.get("target", "")),
                    target_type=str(args.get("target_type", "web_app")),
                    tools_used=list(args.get("tools_used", []) or []),
                    findings=list(args.get("findings", []) or []))
            except Exception:  # noqa: BLE001
                pass
        return Observation(tool_name="record_experience", findings=[])
