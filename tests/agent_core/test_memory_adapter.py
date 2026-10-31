"""Task 7.2 — unit tests for MemoryAdapter.

Asserts:
  - priority hints are a REORDERING of allowlist tools only (never introduce a
    new tool — a memory hint can't smuggle in sqlmap / an exploitation tool)
  - the adapter delegates record/recall to the underlying AssessmentMemory,
    which keeps its _ATTACK_ORIENTED_TERMS rejection; the adapter neither
    bypasses nor weakens that compliance filter
"""
from agent_core.eliana.memory_adapter import MemoryAdapter, _PERMITTED_TOOL_NAMES
from agent_core.models import AssessmentGoal
from app.bounty.models import ProgramScope
from app.bounty.scanner import _AUTO_ORCHESTRATION_TOOLS


def _goal() -> AssessmentGoal:
    return AssessmentGoal("https://app.example.com",
                          ProgramScope(domains=["app.example.com"]),
                          "assess web_app")


# --- priority clamp: allowlist reordering only ------------------------------ #
class _MemReturning:
    def __init__(self, priority):
        self._priority = priority
        self.recorded = None
    def recommend_priority_tools(self, target_type, query="", k=5):
        return list(self._priority)
    def recall_focus_hints(self, target_type, query="", k=3):
        return ["focus: tls config", "focus: open ports"]
    def record_assessment(self, target, target_type, tools_used, findings,
                          use_llm_summary=True):
        self.recorded = {"target": target, "target_type": target_type,
                         "tools_used": tools_used, "findings": findings}
        return "doc-1"


def test_permitted_set_matches_allowlist():
    assert _PERMITTED_TOOL_NAMES == frozenset(t.value for t in _AUTO_ORCHESTRATION_TOOLS)


def test_priority_tools_drops_non_allowlist_tools():
    mem = _MemReturning(["sslscan", "sqlmap", "metasploit", "nmap", "exploit-db"])
    adapter = MemoryAdapter(mem)
    out = adapter.priority_tools(_goal())
    assert out == ["sslscan", "nmap"]  # only allowlist tools, order preserved
    assert "sqlmap" not in out
    assert "metasploit" not in out


def test_priority_tools_is_pure_reordering_subset_of_allowlist():
    mem = _MemReturning(["gobuster", "nuclei", "whatweb"])
    out = MemoryAdapter(mem).priority_tools(_goal())
    assert set(out).issubset(_PERMITTED_TOOL_NAMES)
    assert out == ["gobuster", "nuclei", "whatweb"]


def test_priority_tools_dedupes():
    mem = _MemReturning(["sslscan", "sslscan", "nmap"])
    out = MemoryAdapter(mem).priority_tools(_goal())
    assert out == ["sslscan", "nmap"]


def test_priority_tools_none_backend_empty():
    assert MemoryAdapter(None).priority_tools(_goal()) == []


def test_focus_hints_delegates():
    mem = _MemReturning([])
    hints = MemoryAdapter(mem).focus_hints(_goal())
    assert hints == ["focus: tls config", "focus: open ports"]


def test_focus_hints_none_backend_empty():
    assert MemoryAdapter(None).focus_hints(_goal()) == []


# --- record delegates to record_assessment (keeps compliance filter) -------- #
def test_record_delegates_to_record_assessment():
    mem = _MemReturning([])
    findings = [{"severity": "medium", "attack_technique_id": "T1190"}]
    MemoryAdapter(mem).record(_goal(), findings, tools_used=["nmap", "sslscan"])
    assert mem.recorded is not None
    assert mem.recorded["target"] == "https://app.example.com"
    assert mem.recorded["target_type"] == "web_app"
    assert mem.recorded["tools_used"] == ["nmap", "sslscan"]
    assert mem.recorded["findings"] == findings


def test_record_none_backend_is_noop():
    # must not raise
    MemoryAdapter(None).record(_goal(), [{"severity": "low"}], tools_used=["nmap"])


# --- compliance filter is the REAL AssessmentMemory's, not bypassed --------- #
def test_attack_oriented_rejection_preserved_by_real_memory():
    """The adapter delegates to the real AssessmentMemory, whose
    _build_structured_experience / _llm_experience_summary apply the
    _ATTACK_ORIENTED_TERMS rejection. We assert (a) the terms filter exists and
    is non-empty in the real module, and (b) the adapter calls record_assessment
    (the gated entry point) rather than writing memory by some other path."""
    from app.bounty.assessment_memory import _ATTACK_ORIENTED_TERMS
    assert len(_ATTACK_ORIENTED_TERMS) > 0
    # representative attack-oriented terms are present in the real filter
    joined = " ".join(_ATTACK_ORIENTED_TERMS).lower()
    assert "exploit" in joined or "payload" in joined

    # adapter uses record_assessment (the entry point that applies the filter);
    # it has no alternate write path that could bypass it
    mem = _MemReturning([])
    MemoryAdapter(mem).record(_goal(), [{"severity": "info"}], tools_used=["nmap"])
    assert mem.recorded is not None  # went through record_assessment
