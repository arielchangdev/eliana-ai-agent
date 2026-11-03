"""Task 6.3 — assembly/integration wiring (eliana-agent-live-wiring).

Two end-to-end-打通 proofs:
  1. The PlanningLoop FORWARDS the gate-built ctx into ToolInvoker.invoke
     (so the server scans exactly the gated target) — Property 1.
  2. The assembled TelegramRuntime routes the completed AssessmentOutcome into
     AgentRunPersister.persist (so an agent run is actually written to bounty.db).

All fake/spy — no real Ollama/Kali/scan, no real Telegram, no real db.
"""
import asyncio
import importlib.util
import os

import pytest

from agent_core.guardrail import GuardrailGate
from agent_core.planning_loop import PlanningLoop
from agent_core.models import (
    AssessmentGoal, DecisionKind, GateContext, PlannerDecision, ToolCall,
)
from app.bounty.models import ProgramScope

from tests.agent_core.loop_fakes import (
    ScriptedPlanner, FakeGate, FakeTools, StubAuthorizer, scope,
)

AUTH_TARGET = "https://app.example.com"


# --------------------------------------------------------------------------- #
# Part 1 — loop forwards ctx into invoke (Property 1)
# --------------------------------------------------------------------------- #
def test_loop_forwards_ctx_into_invoke():
    """The loop must pass the ctx it built from the goal into invoke — not drop
    it (that was the root-cause structural bug). FakeTools records every ctx it
    received; we assert it saw a GateContext carrying the goal's target."""
    planner = ScriptedPlanner([
        PlannerDecision(kind=DecisionKind.INVOKE_TOOL,
                        tool_call=ToolCall("nmap", {}), rationale="recon"),
        PlannerDecision(kind=DecisionKind.STOP, rationale="done"),
    ])
    gate = FakeGate(mode="allow")
    tools = FakeTools(findings_per_call=[
        {"severity": "info", "attack_technique_id": "T1046"}])
    goal = AssessmentGoal(target_url=AUTH_TARGET, scope=scope(),
                          description="assess", max_steps=3)
    loop = PlanningLoop(planner=planner, gate=gate, tools=tools,
                        authorizer=StubAuthorizer(ok=True), memory=None,
                        max_steps=3)
    asyncio.run(loop.run(goal))

    # invoke ran at least once and ALWAYS received a ctx (never None for a scan)
    assert tools.invoke_calls >= 1
    assert tools.seen_ctx, "loop never forwarded any ctx"
    first_ctx = tools.seen_ctx[0]
    assert isinstance(first_ctx, GateContext), first_ctx
    assert first_ctx.target_url == AUTH_TARGET
    # the ctx carries the goal's scope + authorizer (built by the loop, not the
    # planner) — the planner never supplies the target
    assert first_ctx.scope is goal.scope


def test_loop_ctx_target_is_goal_target_not_planner_arguments():
    """Even if the planner proposes adversarial call.arguments, the ctx the loop
    forwards carries the GOAL target, independent of call.arguments."""
    planner = ScriptedPlanner([
        PlannerDecision(kind=DecisionKind.INVOKE_TOOL,
                        tool_call=ToolCall("nmap", {"target": "evil.example"}),
                        rationale="adversarial"),
        PlannerDecision(kind=DecisionKind.STOP, rationale="done"),
    ])
    gate = FakeGate(mode="allow")
    tools = FakeTools()
    goal = AssessmentGoal(target_url=AUTH_TARGET, scope=scope(), max_steps=2)
    loop = PlanningLoop(planner=planner, gate=gate, tools=tools,
                        authorizer=StubAuthorizer(ok=True), max_steps=2)
    asyncio.run(loop.run(goal))
    assert tools.seen_ctx[0].target_url == AUTH_TARGET
    assert tools.seen_ctx[0].target_url != "evil.example"


# --------------------------------------------------------------------------- #
# Part 2 — assembled runtime routes the outcome into persist
# --------------------------------------------------------------------------- #
def _load_telegram_runtime():
    """Load the hyphenated eliana-integration/telegram_runtime.py by path."""
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    path = os.path.join(repo_root, "eliana-integration", "telegram_runtime.py")
    spec = importlib.util.spec_from_file_location("telegram_runtime_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _SpyPersister:
    def __init__(self):
        self.persisted = []
    async def persist(self, outcome):
        self.persisted.append(outcome)
        return "scan-id-123"


class _FakeLoop:
    def __init__(self, outcome):
        self._outcome = outcome
    async def run(self, goal):
        return self._outcome


class _FakeBot:
    def __init__(self):
        self.sent = []
    async def send_message(self, chat_id, text):
        self.sent.append((chat_id, text))


class _FakeApp:
    def __init__(self):
        self.bot = _FakeBot()


class _FakeOutcome:
    def __init__(self, findings, reason="step budget reached"):
        self.findings = findings
        self.stopped_reason = reason
        class _Trace:
            def __init__(self, goal):
                self.goal = goal
                self.steps = []
        self.trace = _Trace(AssessmentGoal(target_url=AUTH_TARGET,
                                           scope=scope(), max_steps=3))


def test_runtime_routes_outcome_into_persister():
    """The assembled runtime, after loop.run completes with a real outcome,
    hands that exact outcome to AgentRunPersister.persist."""
    tr = _load_telegram_runtime()
    outcome = _FakeOutcome(findings=[
        {"severity": "info", "attack_technique_id": "T1046",
         "affected_endpoint": "h:80/tcp", "tool": "nmap"}])
    spy = _SpyPersister()
    rt = tr.TelegramRuntime(
        agent={"loop": _FakeLoop(outcome), "persister": spy})
    rt._app = _FakeApp()

    # update is only used for the initial reply in _start_...; _run_agent_
    # assessment uses self._app.bot for the result message, so a None update is
    # fine here (we call _run_agent_assessment directly).
    asyncio.run(rt._run_agent_assessment(
        update=None, chat_id="42", target=AUTH_TARGET, scope=scope()))

    # the completed outcome was routed into persist exactly once
    assert len(spy.persisted) == 1
    assert spy.persisted[0] is outcome
    # and the user got an honest result message
    assert rt._app.bot.sent, "no result message sent"


def test_runtime_planner_unavailable_does_not_persist():
    """If the planner is unavailable, the run falls back to legacy and the agent
    persister is NOT called (nothing real to persist)."""
    tr = _load_telegram_runtime()
    from agent_core.planning_loop import PLANNER_UNAVAILABLE_REASON
    outcome = _FakeOutcome(findings=[], reason=PLANNER_UNAVAILABLE_REASON)
    spy = _SpyPersister()

    # minimal scanner stub so _fallback_to_legacy doesn't explode before we can
    # assert; it only needs _assessment_memory attr + is not actually scanned.
    class _Scanner:
        _assessment_memory = None
    rt = tr.TelegramRuntime(
        scanner=_Scanner(), agent={"loop": _FakeLoop(outcome), "persister": spy})
    rt._app = _FakeApp()

    # _fallback_to_legacy schedules a legacy task via asyncio.create_task; we
    # only care that persist was NOT called. Swallow the scheduled task.
    async def _go():
        await rt._run_agent_assessment(update=None, chat_id="7",
                                       target=AUTH_TARGET, scope=scope())
        # cancel any scheduled fallback task so the loop can close cleanly
        for t in list(rt._running_assessments.values()):
            t.cancel()
    asyncio.run(_go())
    assert spy.persisted == [], "planner-unavailable must not persist an agent run"


# --------------------------------------------------------------------------- #
# Regression — logger bug: the post-persist log call must NOT raise, so a
# SUCCESSFUL persist is never misreported as "persistence failed" and the
# result message is still sent. (This bug slipped through before because no
# test asserted the stdlib logger call was well-formed.)
# --------------------------------------------------------------------------- #
import logging


class _Capture(logging.Handler):
    """Collect (level, formatted-message) for a named logger, and FAIL loudly if
    a record cannot be formatted — which is exactly what the structlog-style
    kwargs bug would do inside the stdlib logger path."""
    def __init__(self):
        super().__init__()
        self.records = []
        self.format_errors = []
    def emit(self, record):
        try:
            self.records.append((record.levelno, record.getMessage()))
        except Exception as exc:  # noqa: BLE001
            self.format_errors.append(str(exc))


def _attach(logger_name):
    lg = logging.getLogger(logger_name)
    cap = _Capture()
    lg.addHandler(cap)
    lg.setLevel(logging.INFO)
    return lg, cap


def test_runtime_persist_log_does_not_raise_and_result_sent():
    """After a successful persist, the 'agent_run_persisted' log must be a
    well-formed stdlib call (no kwargs blow-up), NO 'persistence failed' warning
    is emitted, and the result message is sent. Directly guards the logger bug
    that made a successful persist look failed and blocked the Telegram reply."""
    tr = _load_telegram_runtime()
    lg, cap = _attach("eliana.telegram")
    try:
        outcome = _FakeOutcome(findings=[
            {"severity": "info", "attack_technique_id": "T1046",
             "affected_endpoint": "h:80/tcp", "tool": "nmap"}])
        spy = _SpyPersister()
        rt = tr.TelegramRuntime(
            agent={"loop": _FakeLoop(outcome), "persister": spy})
        rt._app = _FakeApp()
        asyncio.run(rt._run_agent_assessment(
            update=None, chat_id="42", target=AUTH_TARGET, scope=scope()))

        # persist ran
        assert len(spy.persisted) == 1
        # the stdlib logger never choked on the log record (the bug's signature)
        assert cap.format_errors == [], cap.format_errors
        msgs = [m for _lvl, m in cap.records]
        # success log present, carrying the scan_id + target
        assert any("agent_run_persisted" in m and "scan-id-123" in m for m in msgs), msgs
        # and NO misleading "persistence failed" warning
        assert not any("persistence failed" in m for m in msgs), msgs
        # the user actually got the result message
        assert rt._app.bot.sent, "result message not sent"
    finally:
        lg.removeHandler(cap)


def test_runtime_result_send_failure_surfaces_cause():
    """If the Telegram send genuinely fails, the warning now carries the real
    exception cause (not a bare 'failed'), so send failures are diagnosable."""
    tr = _load_telegram_runtime()
    lg, cap = _attach("eliana.telegram")
    try:
        outcome = _FakeOutcome(findings=[])
        spy = _SpyPersister()

        class _BoomBot:
            async def send_message(self, chat_id, text):
                raise RuntimeError("telegram 503 boom")
        class _BoomApp:
            bot = _BoomBot()

        rt = tr.TelegramRuntime(
            agent={"loop": _FakeLoop(outcome), "persister": spy})
        rt._app = _BoomApp()
        asyncio.run(rt._run_agent_assessment(
            update=None, chat_id="42", target=AUTH_TARGET, scope=scope()))

        assert cap.format_errors == []
        msgs = [m for _lvl, m in cap.records]
        # the real cause is surfaced in the warning
        assert any("agent result send failed" in m and "telegram 503 boom" in m
                   for m in msgs), msgs
    finally:
        lg.removeHandler(cap)


# --------------------------------------------------------------------------- #
# Observability — LocalPlannerLLM logs the raw model response + parsed decision,
# so a surprising STOP (model declining to pick a tool) is visible in journald.
# --------------------------------------------------------------------------- #
def test_planner_logs_raw_response_and_decision():
    """decide() must log the raw model response AND the parsed decision. Uses a
    stubbed _chat so no real Ollama is contacted."""
    from agent_core.eliana.local_planner import LocalPlannerLLM
    from agent_core.models import PerceivedState, AssessmentGoal, ToolSpec

    lg, cap = _attach("eliana.planner")
    try:
        planner = LocalPlannerLLM()
        # stub the transport: return a STOP-shaped JSON (reproduces the 3b
        # "declines to pick a tool" case we saw on the VM) — no network.
        raw_json = '{"action": "stop", "rationale": "nothing actionable yet"}'
        planner._chat = lambda payload: raw_json  # type: ignore

        state = PerceivedState(
            goal=AssessmentGoal(target_url=AUTH_TARGET, scope=scope(),
                                description="assess", max_steps=3),
            findings_so_far=[], steps_taken=[],
            available_tools=[ToolSpec("recon_scan", "recon")])
        decision = asyncio.run(planner.decide(state))

        assert decision.kind == DecisionKind.STOP
        assert cap.format_errors == []
        msgs = [m for _lvl, m in cap.records]
        # raw response logged (so we can see WHAT the model said)
        assert any("planner_raw_response" in m and "nothing actionable" in m
                   for m in msgs), msgs
        # parsed decision logged (kind=stop)
        assert any("planner_decision" in m and "kind=stop" in m for m in msgs), msgs
    finally:
        lg.removeHandler(cap)


def test_planner_logs_invoke_decision_with_tool():
    """When the model picks a tool, the decision log names that tool."""
    from agent_core.eliana.local_planner import LocalPlannerLLM
    from agent_core.models import PerceivedState, AssessmentGoal, ToolSpec

    lg, cap = _attach("eliana.planner")
    try:
        planner = LocalPlannerLLM()
        planner._chat = lambda payload: (  # type: ignore
            '{"action": "invoke_tool", "tool": "nmap", "rationale": "port recon"}')
        state = PerceivedState(
            goal=AssessmentGoal(target_url=AUTH_TARGET, scope=scope(),
                                description="assess", max_steps=3),
            findings_so_far=[], steps_taken=[],
            available_tools=[ToolSpec("recon_scan", "recon")])
        decision = asyncio.run(planner.decide(state))

        assert decision.kind == DecisionKind.INVOKE_TOOL
        assert decision.tool_call.tool_name == "nmap"
        msgs = [m for _lvl, m in cap.records]
        assert any("planner_decision" in m and "tool=nmap" in m for m in msgs), msgs
    finally:
        lg.removeHandler(cap)
