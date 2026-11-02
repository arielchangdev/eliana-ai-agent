"""Task 4.2–4.5 — real-parser reuse in `_parse_recon_output`
(eliana-agent-live-wiring).

A stub cannot hide a broken wire: these tests feed the SAME fixture bytes the
legacy pipeline would see through the agent path and assert REAL findings come
out (correct severity / endpoint / ATT&CK label), that the agent path is
shape-equivalent to the legacy `_parse_tool_output` pipeline, that empty /
malformed output yields zero findings (no fabricated placeholder), and that the
projection surfaced to the planner never leaks raw payloads / evidence.

Fixtures are HAND-CRAFTED per each parser's real field expectations (the repo
had no pre-existing parser corpus); see tool_output_fixtures.py. Because both
paths parse identical bytes, the equivalence test (4.3) is a meaningful
anti-drift guard.

  Property 3: agent-path findings equal legacy findings in shape
  Property 4: honest empty — no fabricated findings
  Property 5: honest finding projection (severity + ATT&CK only, no raw payload)
"""
import pytest
from hypothesis import given, settings, strategies as st

from agent_core.eliana.mcp_server import ElianaMCPServer, _project_finding
from agent_core.models import Observation

from app.bounty.scanner import ScanEngine, deduplicate_findings
from app.bounty.attack_mapping import map_finding_to_attack
from app.bounty.enums import ScanTool, SeverityLevel
from app.bounty.models import Vulnerability

import tests.agent_core.tool_output_fixtures as fx


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _server() -> ElianaMCPServer:
    """A server wired to the REAL ScanEngine (no attack_mapper injection: the
    rewritten _parse_recon_output calls the module-level map_finding_to_attack
    directly, exactly as the legacy execute_scan does)."""
    return ElianaMCPServer(scan_engine=ScanEngine())


def _legacy_shape(tool: ScanTool, raw: str, target: str) -> list[tuple]:
    """Reproduce the legacy execute_scan pipeline and return comparable shape
    tuples (severity, endpoint, tool_source, attack_technique_id)."""
    engine = ScanEngine()
    vulns = engine._parse_tool_output(tool, raw, scan_id="", target=target)
    vulns = deduplicate_findings(vulns)
    shapes = []
    for v in vulns:
        tech = map_finding_to_attack(v.tool_source, v.title or "", v.description or "")
        tid = tech.technique_id if tech is not None else None
        shapes.append((v.severity.value, v.affected_endpoint, v.tool_source.value, tid))
    return shapes


def _agent_shape(obs: Observation) -> list[tuple]:
    return [
        (f["severity"], f["affected_endpoint"], f["tool"],
         f.get("attack_technique_id"))
        for f in obs.findings
    ]


TARGET = "198.51.100.23"

# Expected minimum findings + a representative ATT&CK id per tool (from the
# hand-crafted fixtures; verified against the real parsers + _ATTACK_RULES).
_EXPECTED = {
    ScanTool.NMAP:     {"count": 2, "techniques": {"T1046"}},
    ScanTool.NUCLEI:   {"count": 3, "techniques": {"T1190"}},
    ScanTool.NIKTO:    {"count": 4, "techniques": {"T1190", "T1083"}},
    ScanTool.WHATWEB:  {"count": 1, "techniques": {"T1592.002"}},
    ScanTool.WAFW00F:  {"count": 1, "techniques": {"T1590.004"}},
    ScanTool.DNSRECON: {"count": 1, "techniques": {"T1590"}},
    ScanTool.SSLSCAN:  {"count": 1, "techniques": {"T1600"}},
    ScanTool.GOBUSTER: {"count": 4, "techniques": {"T1083"}},
}


# --------------------------------------------------------------------------- #
# Task 4.2 — parser tests on real fixtures (real findings, severities, ATT&CK)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("tool", list(_EXPECTED.keys()), ids=lambda t: t.value)
def test_fixture_yields_real_findings_with_attack_labels(tool):
    srv = _server()
    raw = fx.load_fixture(tool, "finding")
    obs = srv._parse_recon_output(tool.value, raw, TARGET)

    exp = _EXPECTED[tool]
    assert len(obs.findings) == exp["count"], (
        f"{tool.value}: expected {exp['count']} findings, got {len(obs.findings)}")

    # every finding carries a real severity (a SeverityLevel value) + endpoint
    valid_sev = {s.value for s in SeverityLevel}
    for f in obs.findings:
        assert f["severity"] in valid_sev
        assert f["affected_endpoint"], f"empty endpoint in {f}"
        assert f["tool"] == tool.value

    # ATT&CK labels present and drawn from the real rule table for this tool
    seen_tech = {f.get("attack_technique_id") for f in obs.findings}
    assert exp["techniques"].issubset(seen_tech), (
        f"{tool.value}: expected techniques {exp['techniques']} "
        f"to appear, saw {seen_tech}")


def test_nmap_open_port_maps_to_t1046():
    """Spot-check the design's named example: nmap open-port -> T1046."""
    srv = _server()
    obs = srv._parse_recon_output(
        ScanTool.NMAP.value, fx.load_fixture(ScanTool.NMAP, "finding"), TARGET)
    assert obs.findings
    for f in obs.findings:
        assert f["severity"] == "info"
        assert f["attack_technique_id"] == "T1046"
        assert f["attack_technique_name"] == "Network Service Discovery"
        assert f["affected_endpoint"].startswith(TARGET + ":")


def test_sslscan_deprecated_protocol_is_medium():
    srv = _server()
    obs = srv._parse_recon_output(
        ScanTool.SSLSCAN.value, fx.load_fixture(ScanTool.SSLSCAN, "finding"), TARGET)
    assert len(obs.findings) == 1
    assert obs.findings[0]["severity"] == "medium"
    assert obs.findings[0]["attack_technique_id"] == "T1600"


# --------------------------------------------------------------------------- #
# Task 4.3 — equivalence: agent path vs legacy _parse_tool_output (SAME input)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("tool", list(_EXPECTED.keys()), ids=lambda t: t.value)
def test_agent_path_shape_equivalent_to_legacy(tool):
    """The agent path's findings for a fixture are equivalent in shape
    (severity, endpoint, tool_source, ATT&CK id) to the legacy pipeline's
    output for the SAME fixture bytes — binding the two paths so they cannot
    drift."""
    raw = fx.load_fixture(tool, "finding")
    srv = _server()
    agent = _agent_shape(srv._parse_recon_output(tool.value, raw, TARGET))
    legacy = _legacy_shape(tool, raw, TARGET)
    assert agent == legacy, (
        f"{tool.value}: agent/legacy shape drift\n"
        f"  agent : {agent}\n  legacy: {legacy}")


def test_equivalence_holds_across_all_fixtures_jointly():
    """A single aggregate assertion over all 8 tools, so a drift in any one
    tool fails this test too (defense against a silently-skipped param)."""
    srv = _server()
    for tool in _EXPECTED:
        raw = fx.load_fixture(tool, "finding")
        assert _agent_shape(srv._parse_recon_output(tool.value, raw, TARGET)) \
            == _legacy_shape(tool, raw, TARGET), tool.value


# --------------------------------------------------------------------------- #
# Task 4.4 — honest empty + malformed (zero findings, no fabrication)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("tool", list(_EXPECTED.keys()), ids=lambda t: t.value)
def test_empty_output_yields_zero_findings(tool):
    """Empty/whitespace output -> zero findings; the old {'severity':'info'}
    fabricated placeholder must be gone."""
    srv = _server()
    obs = srv._parse_recon_output(tool.value, fx.load_fixture(tool, "empty"), TARGET)
    assert obs.findings == [], f"{tool.value}: empty output fabricated a finding"


@pytest.mark.parametrize("tool", list(_EXPECTED.keys()), ids=lambda t: t.value)
def test_malformed_output_matches_legacy(tool):
    """Malformed output -> agent path yields exactly what the legacy parser
    yields for the same bytes (the legacy try/except turns garbage into []).
    sslscan is the one tool whose parser emits an informational finding for any
    non-empty input — the equivalence assertion captures that honestly rather
    than hard-coding zero."""
    srv = _server()
    raw = fx.load_fixture(tool, "malformed")
    agent = _agent_shape(srv._parse_recon_output(tool.value, raw, TARGET))
    legacy = _legacy_shape(tool, raw, TARGET)
    assert agent == legacy, f"{tool.value}: malformed drift agent={agent} legacy={legacy}"


def test_most_malformed_fixtures_are_zero_findings():
    """Honest sanity check: every malformed fixture except sslscan yields zero
    findings (documents the sslscan non-empty-always-INFO behaviour explicitly
    instead of hiding it)."""
    srv = _server()
    for tool in _EXPECTED:
        obs = srv._parse_recon_output(tool.value, fx.load_fixture(tool, "malformed"), TARGET)
        if tool is ScanTool.SSLSCAN:
            assert len(obs.findings) == 1 and obs.findings[0]["severity"] == "info"
        else:
            assert obs.findings == [], f"{tool.value} malformed should be empty"


def test_no_raw_payload_in_any_fixture_projection():
    """Across every findings-bearing fixture, the projected Observation entries
    never carry raw_output/evidence (the sensitive payload stays out of the
    planner-facing surface)."""
    srv = _server()
    for tool in _EXPECTED:
        obs = srv._parse_recon_output(tool.value, fx.load_fixture(tool, "finding"), TARGET)
        for f in obs.findings:
            assert "raw_output" not in f
            assert "evidence" not in f
            # the short excerpt is length-capped and non-sensitive
        assert len(obs.raw_excerpt) <= 120


# --------------------------------------------------------------------------- #
# Task 4.5 — property: honest finding projection (hypothesis, >=100 iterations)
# --------------------------------------------------------------------------- #
_sev = st.sampled_from(list(SeverityLevel))
_tool = st.sampled_from(list(ScanTool))
_text = st.text(min_size=0, max_size=40)
# a technique id or None (to exercise the "no technique -> ATT&CK unset" branch)
_tech_id = st.one_of(st.none(), st.sampled_from(["T1046", "T1190", "T1083", "T1600"]))


@settings(max_examples=150, deadline=None)
@given(sev=_sev, tool=_tool, title=_text, endpoint=_text,
       raw=st.text(min_size=0, max_size=60), evidence=st.text(min_size=0, max_size=60),
       tech_id=_tech_id)
def test_p5_projection_is_honest(sev, tool, title, endpoint, raw, evidence, tech_id):
    """For any generated finding, _project_finding surfaces severity + ATT&CK
    labels + non-sensitive identifying fields only — never raw_output/evidence —
    and leaves ATT&CK fields unset when no technique is mapped."""
    v = Vulnerability(
        severity=sev, title=title, affected_endpoint=endpoint,
        tool_source=tool, raw_output=raw, evidence=evidence,
    )
    if tech_id is not None:
        v.attack_technique_id = tech_id
        v.attack_technique_name = "Some Technique"
        v.attack_tactic = "TA0007 Discovery"

    f = _project_finding(v)

    # severity + ATT&CK + non-sensitive identifying fields only
    assert f["severity"] == sev.value
    assert f["tool"] == tool.value
    assert f["title"] == (title or "")
    assert f["affected_endpoint"] == (endpoint or "")

    # NEVER leak the raw payload / evidence into the planner-facing projection.
    # Assert by key: the sensitive fields are structurally absent. (A value
    # check would be brittle since generated title/endpoint text could coincide
    # with raw/evidence text — the contract is about which keys are surfaced.)
    assert "raw_output" not in f
    assert "evidence" not in f
    assert set(f.keys()) <= {
        "severity", "title", "affected_endpoint", "tool",
        "attack_technique_id", "attack_technique_name", "attack_tactic",
    }

    # ATT&CK present iff a technique was mapped; never fabricated otherwise
    if tech_id is not None:
        assert f["attack_technique_id"] == tech_id
        assert f["attack_technique_name"] == "Some Technique"
    else:
        assert "attack_technique_id" not in f
        assert "attack_technique_name" not in f
        assert "attack_tactic" not in f
