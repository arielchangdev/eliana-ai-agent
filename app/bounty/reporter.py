"""Bounty module vulnerability report generator.

Implements the ReportGenerator class with CVSS calculation, template selection,
bounty estimation, and LLM prompt construction.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from cvss import CVSS3

from app.bounty.enums import PlatformType, ReportStatus, SeverityLevel
from app.bounty.errors import ReportGenerationError
from app.bounty.models import (
    BountyProgram,
    BountyRange,
    CvssScore,
    Report,
    Vulnerability,
)

logger = logging.getLogger(__name__)


# --- Report Template Definitions ---


@dataclass
class ReportTemplate:
    """Report format template."""

    platform: PlatformType
    name: str = ""
    sections: list[str] = field(default_factory=list)
    format_hint: str = ""


# Platform-specific templates
_HACKERONE_TEMPLATE = ReportTemplate(
    platform=PlatformType.HACKERONE,
    name="HackerOne Standard",
    sections=[
        "title",
        "vulnerability_type",
        "severity",
        "description",
        "steps_to_reproduce",
        "impact",
        "supporting_material",
        "remediation",
    ],
    format_hint=(
        "HackerOne format: Use markdown. Include clear reproduction steps "
        "numbered sequentially. Attach evidence as inline images or code blocks. "
        "Impact section should reference CIA triad."
    ),
)

_BUGCROWD_TEMPLATE = ReportTemplate(
    platform=PlatformType.BUGCROWD,
    name="Bugcrowd Standard",
    sections=[
        "title",
        "vulnerability_type",
        "url_endpoint",
        "severity",
        "description",
        "proof_of_concept",
        "impact",
        "remediation_advice",
    ],
    format_hint=(
        "Bugcrowd format: Be concise. PoC should include HTTP requests/responses. "
        "Use Bugcrowd VRT taxonomy for vulnerability type. "
        "Impact should state business risk clearly."
    ),
)

_INTIGRITI_TEMPLATE = ReportTemplate(
    platform=PlatformType.INTIGRITI,
    name="Intigriti Standard",
    sections=[
        "title",
        "domain_endpoint",
        "severity",
        "description",
        "steps_to_reproduce",
        "impact",
        "attachments",
        "suggested_fix",
    ],
    format_hint=(
        "Intigriti format: Domain/endpoint must be clearly specified. "
        "Steps should be reproducible by a third party. "
        "Include browser/tool version in attachments section."
    ),
)

_YESWEHACK_TEMPLATE = ReportTemplate(
    platform=PlatformType.YESWEHACK,
    name="YesWeHack Standard",
    sections=[
        "title",
        "scope",
        "severity",
        "technical_description",
        "exploitation_steps",
        "impact_analysis",
        "evidence",
        "recommendation",
    ],
    format_hint=(
        "YesWeHack format: Technical description should include attack vector details. "
        "Exploitation steps must demonstrate full chain. "
        "Evidence should include timestamps and tool versions."
    ),
)

_PLATFORM_TEMPLATES: dict[PlatformType, ReportTemplate] = {
    PlatformType.HACKERONE: _HACKERONE_TEMPLATE,
    PlatformType.BUGCROWD: _BUGCROWD_TEMPLATE,
    PlatformType.INTIGRITI: _INTIGRITI_TEMPLATE,
    PlatformType.YESWEHACK: _YESWEHACK_TEMPLATE,
}


# --- CVSS Vector Mapping ---

# Mapping from SeverityLevel to a representative CVSS v3.1 vector string.
# These are reasonable defaults when a vulnerability does not carry its own vector.
_SEVERITY_TO_VECTOR: dict[SeverityLevel, str] = {
    SeverityLevel.CRITICAL: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    SeverityLevel.HIGH: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    SeverityLevel.MEDIUM: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    SeverityLevel.LOW: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
    SeverityLevel.INFO: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
}


# --- Severity Threshold for Report Generation ---

# Severity levels that trigger automatic report generation (medium+)
_REPORT_TRIGGER_SEVERITIES: set[SeverityLevel] = {
    SeverityLevel.MEDIUM,
    SeverityLevel.HIGH,
    SeverityLevel.CRITICAL,
}


def should_generate_report(vulnerability: Vulnerability) -> bool:
    """Determine whether a vulnerability should trigger report generation (pure function).

    Per Requirements 4.1: only MEDIUM, HIGH, CRITICAL severity levels trigger
    report generation. LOW and INFO do NOT trigger.

    Args:
        vulnerability: The vulnerability to evaluate.

    Returns:
        True if the vulnerability should trigger report generation, False otherwise.
    """
    return vulnerability.severity in _REPORT_TRIGGER_SEVERITIES


# --- Pure Functions ---


def calculate_cvss(vulnerability: Vulnerability) -> CvssScore:
    """Calculate CVSS v3.1 score.

    Uses the cvss PyPI package to compute the base score from a CVSS vector
    string. If the vulnerability does not carry an explicit vector, a default
    vector is selected based on the severity level.

    Args:
        vulnerability: The vulnerability to score.

    Returns:
        CvssScore with base_score, vector_string, and severity_label.
    """
    # Determine the vector string: use existing evidence if it looks like
    # a valid CVSS vector, otherwise fall back to severity-based default.
    vector_string = ""
    if vulnerability.evidence and vulnerability.evidence.startswith("CVSS:3.1/"):
        vector_string = vulnerability.evidence.strip()
    elif vulnerability.raw_output and "CVSS:3.1/" in vulnerability.raw_output:
        # Try to extract vector from raw output
        for part in vulnerability.raw_output.split():
            if part.startswith("CVSS:3.1/"):
                vector_string = part.strip()
                break

    if not vector_string:
        vector_string = _SEVERITY_TO_VECTOR.get(
            vulnerability.severity,
            _SEVERITY_TO_VECTOR[SeverityLevel.INFO],
        )

    try:
        cvss_obj = CVSS3(vector_string)
        base_score = cvss_obj.base_score
        severity_label = cvss_obj.severities()[0]
    except Exception:
        # If parsing fails, fall back to the severity-based default
        fallback_vector = _SEVERITY_TO_VECTOR.get(
            vulnerability.severity,
            _SEVERITY_TO_VECTOR[SeverityLevel.INFO],
        )
        try:
            cvss_obj = CVSS3(fallback_vector)
            base_score = cvss_obj.base_score
            severity_label = cvss_obj.severities()[0]
            vector_string = fallback_vector
        except Exception:
            # Ultimate fallback - should never reach here
            base_score = 0.0
            severity_label = "None"
            vector_string = _SEVERITY_TO_VECTOR[SeverityLevel.INFO]

    return CvssScore(
        base_score=base_score,
        severity_label=severity_label,
        vector_string=vector_string,
    )


def select_template(platform: PlatformType) -> ReportTemplate:
    """Select the report format template for a given platform (pure function).

    Each Bug Bounty platform has its own report format expectations. This function
    returns the appropriate template containing section ordering and formatting hints.

    Args:
        platform: The target Bug Bounty platform.

    Returns:
        ReportTemplate for the specified platform.
    """
    return _PLATFORM_TEMPLATES[platform]


# --- Default Bounty Tables by Severity ---

# Default bounty multipliers when a program doesn't provide explicit ranges.
# Applied as multiplier against the program's bounty_range_high.
_DEFAULT_BOUNTY_TABLE: dict[str, tuple[float, float]] = {
    "Critical": (0.70, 1.00),
    "High": (0.40, 0.70),
    "Medium": (0.15, 0.40),
    "Low": (0.05, 0.15),
    "None": (0.0, 0.0),
}


def estimate_bounty_range(cvss_score: float, program: BountyProgram) -> BountyRange:
    """Estimate bounty range based on CVSS score and program bounty table (pure function).

    Uses the program's bounty_range_low and bounty_range_high fields along with
    the CVSS severity to estimate the expected payout range.

    The estimation logic:
    - Map CVSS score to severity label
    - Use severity-based multipliers against the program's bounty_range_high
    - Confidence is determined by how well-defined the program's bounty info is

    Args:
        cvss_score: The CVSS v3.1 base score (0.0 to 10.0).
        program: The BountyProgram containing bounty range information.

    Returns:
        BountyRange with min_usd, max_usd, and confidence level.
    """
    # Map CVSS score to severity label for table lookup
    if cvss_score >= 9.0:
        severity_key = "Critical"
    elif cvss_score >= 7.0:
        severity_key = "High"
    elif cvss_score >= 4.0:
        severity_key = "Medium"
    elif cvss_score >= 0.1:
        severity_key = "Low"
    else:
        severity_key = "None"

    multiplier_low, multiplier_high = _DEFAULT_BOUNTY_TABLE[severity_key]

    # Use the program's bounty range to estimate
    program_max = program.bounty_range_high

    if program_max <= 0.0:
        # No bounty information available
        return BountyRange(min_usd=0.0, max_usd=0.0, confidence="low")

    # Calculate estimated range
    estimated_min = max(program.bounty_range_low, program_max * multiplier_low)
    estimated_max = program_max * multiplier_high

    # Ensure min <= max
    if estimated_min > estimated_max:
        estimated_min = estimated_max

    # Determine confidence based on available information
    if program.bounty_range_high > 0 and program.bounty_range_low > 0:
        confidence = "high"
    elif program.bounty_range_high > 0:
        confidence = "medium"
    else:
        confidence = "low"

    return BountyRange(
        min_usd=round(estimated_min, 2),
        max_usd=round(estimated_max, 2),
        confidence=confidence,
    )


def build_llm_prompt(vulnerability: Vulnerability, template: ReportTemplate) -> str:
    """Construct the LLM inference prompt for report generation (pure function).

    Builds a structured prompt that instructs the Local_LLM to generate a
    vulnerability report following the platform-specific template format.

    Args:
        vulnerability: The vulnerability to generate a report for.
        template: The platform-specific report template.

    Returns:
        A formatted prompt string for the LLM.
    """
    sections_list = chr(10).join(f"  - {section}" for section in template.sections)

    prompt = (
        "You are a professional security researcher writing a Bug Bounty "
        "vulnerability report.\n\n"
        f"## Platform: {template.name}\n"
        f"## Format Instructions: {template.format_hint}\n\n"
        f"## Required Sections:\n{sections_list}\n\n"
        "## Vulnerability Details:\n"
        f"- Title: {vulnerability.title}\n"
        f"- Severity: {vulnerability.severity.value}\n"
        f"- CVE ID: {vulnerability.cve_id or 'N/A'}\n"
        f"- Affected Endpoint: {vulnerability.affected_endpoint}\n"
        f"- Description: {vulnerability.description}\n"
        f"- Evidence: {vulnerability.evidence}\n"
        f"- Tool Source: {vulnerability.tool_source.value}\n"
        f"- Discovered At: {vulnerability.discovered_at.isoformat()}\n\n"
        "## Instructions:\n"
        "1. Write a complete vulnerability report following the platform format above.\n"
        "2. Include clear, step-by-step reproduction instructions.\n"
        "3. Assess the real-world impact considering confidentiality, integrity, "
        "and availability.\n"
        "4. Provide actionable remediation advice.\n"
        "5. Be professional, concise, and technically accurate.\n"
        "6. Use the evidence provided to support your findings.\n\n"
        "Generate the report now:"
    )

    return prompt


# --- LLM response section parsing ---

# Section-heading keyword -> canonical report field. Covers the section names
# used across all four platform templates so the narrative can be split into
# the dashboard's description / reproduction / impact / remediation columns.
_SECTION_ALIASES: dict[str, str] = {
    # description
    "description": "description",
    "technical description": "description",
    "technical_description": "description",
    "summary": "description",
    "vulnerability type": "description",
    # reproduction
    "steps to reproduce": "reproduction",
    "steps_to_reproduce": "reproduction",
    "reproduction": "reproduction",
    "reproduction steps": "reproduction",
    "proof of concept": "reproduction",
    "proof_of_concept": "reproduction",
    "poc": "reproduction",
    "exploitation steps": "reproduction",
    "exploitation_steps": "reproduction",
    # impact
    "impact": "impact",
    "impact analysis": "impact",
    "impact_analysis": "impact",
    "impact assessment": "impact",
    # remediation
    "remediation": "remediation",
    "remediation advice": "remediation",
    "remediation_advice": "remediation",
    "suggested fix": "remediation",
    "suggested_fix": "remediation",
    "recommendation": "remediation",
    "fix": "remediation",
    "mitigation": "remediation",
}

# Headings that are metadata/structure, not narrative body. When seen, their
# body is dropped (not routed to description) so description stays clean. The
# report's title/severity/cvss already live in dedicated columns.
_SKIP_HEADINGS: set[str] = {
    "vulnerability report", "report", "title", "severity", "cve id",
    "cve_id", "cve", "scope", "domain", "endpoint", "url", "url endpoint",
    "url_endpoint", "domain endpoint", "domain_endpoint", "supporting material",
    "attachments", "evidence",
}


def _normalize_heading(text: str) -> str:
    """Strip markdown heading markup/numbering/punctuation and lowercase."""
    t = text.strip().lstrip("#").strip()
    t = t.lstrip("*").rstrip("*").strip()
    # drop leading numbering like "1." / "2)"
    import re as _re
    t = _re.sub(r"^\d+[.)]\s*", "", t)
    t = t.rstrip(":").strip().lower()
    return t


def parse_report_sections(llm_response: str) -> dict:
    """Split an LLM report into {description, reproduction, impact, remediation}.

    Walks markdown-style heading lines (``#``/``##``/``###`` or ``**Bold:**``)
    and routes the body under each heading to a canonical field via
    _SECTION_ALIASES. Content before the first recognized heading, and any
    unrecognized section, falls back into ``description`` so nothing is lost.
    Returns a dict; callers decide how to use it. Pure function (testable).
    """
    fields = {"description": [], "reproduction": [], "impact": [],
              "remediation": [], "_skip": []}
    current = "description"  # pre-heading content goes to description
    matched_any = False

    for raw in (llm_response or "").split(chr(10)):
        line = raw.rstrip()
        stripped = line.strip()
        is_heading = False
        heading_text = ""
        if stripped.startswith("#"):
            is_heading = True
            heading_text = stripped
        elif (stripped.startswith("**") and stripped.endswith("**")
              and len(stripped) <= 60):
            is_heading = True
            heading_text = stripped
        if is_heading:
            key = _normalize_heading(heading_text)
            if key in _SKIP_HEADINGS:
                current = "_skip"
                matched_any = True
                continue
            target = _SECTION_ALIASES.get(key)
            if target is not None:
                current = target
                matched_any = True
                continue  # don't keep the heading line itself
        fields[current].append(line)

    result = {k: chr(10).join(v).strip()
              for k, v in fields.items() if k != "_skip"}
    result["_matched"] = matched_any
    return result


# --- ReportGenerator Class ---


class ReportGenerator:
    """Vulnerability report auto-generator using Local_LLM.

    Orchestrates CVSS calculation, template selection, bounty estimation,
    and LLM-based report generation with fallback to template filling.
    """

    def __init__(self, llm_client=None, quality_threshold: float = 0.6):
        """Initialize ReportGenerator.

        Args:
            llm_client: Optional Local_LLM client instance. If None, only
                template-based generation is available.
            quality_threshold: Minimum LLM quality score (0.0-1.0) to accept
                generated report. Below this, falls back to template filling.
        """
        self._llm_client = llm_client
        self._quality_threshold = quality_threshold

    async def generate_report(
        self, vulnerability: Vulnerability, program: BountyProgram
    ) -> Report:
        """Generate a complete vulnerability report.

        Full flow:
        1. Calculate CVSS score
        2. Select platform template
        3. Estimate bounty range
        4. Attempt LLM generation
        5. Fallback to template if LLM fails or quality is low

        Args:
            vulnerability: The vulnerability to report on.
            program: The BountyProgram the vulnerability belongs to.

        Returns:
            A Report instance ready for user review.

        Raises:
            ReportGenerationError: If both LLM and template fallback fail.
        """
        # Step 1: Calculate CVSS
        cvss_result = calculate_cvss(vulnerability)

        # Step 2: Select template
        template = select_template(program.platform)

        # Step 3: Estimate bounty range
        bounty_range = estimate_bounty_range(cvss_result.base_score, program)

        # Step 4: Attempt LLM generation
        report: Optional[Report] = None
        llm_quality_score = 0.0

        if self._llm_client is not None:
            try:
                prompt = build_llm_prompt(vulnerability, template)
                llm_response = await self._llm_client.generate(prompt)
                llm_quality_score = await self._evaluate_quality(llm_response)

                if llm_quality_score >= self._quality_threshold:
                    report = self._parse_llm_response(
                        llm_response, vulnerability, program,
                        cvss_result, bounty_range
                    )
                    if report:
                        report.llm_quality_score = llm_quality_score
                        logger.info(
                            "LLM report generated for vulnerability %s (quality: %.2f)",
                            vulnerability.id,
                            llm_quality_score,
                        )
                else:
                    logger.warning(
                        "LLM quality score %.2f below threshold %.2f for %s",
                        llm_quality_score,
                        self._quality_threshold,
                        vulnerability.id,
                    )
            except Exception as exc:
                logger.warning(
                    "LLM generation failed for %s: %s, falling back to template",
                    vulnerability.id,
                    exc,
                )

        # Step 5: Fallback to template filling if LLM failed
        if report is None:
            try:
                report = await self.fallback_to_template(vulnerability, template)
                report.cvss = cvss_result
                report.estimated_bounty = bounty_range
                report.program_id = program.id
                report.platform = program.platform
                report.llm_quality_score = llm_quality_score
            except Exception as exc:
                raise ReportGenerationError(
                    f"Both LLM and template fallback failed: {exc}",
                    vulnerability_id=vulnerability.id,
                ) from exc

        # Attach raw scan output as evidence with timestamp (Req 4.4)
        if vulnerability.raw_output:
            timestamp = vulnerability.discovered_at.isoformat()
            evidence_entry = (
                f"[{timestamp}] Tool: {vulnerability.tool_source.value}"
                + chr(10) + vulnerability.raw_output
            )
            if evidence_entry not in report.evidence_attachments:
                report.evidence_attachments.append(evidence_entry)

        return report

    async def fallback_to_template(
        self, vulnerability: Vulnerability, template: ReportTemplate
    ) -> Report:
        """Generate report using structured template filling when LLM fails.

        Fills template sections with available vulnerability data without
        requiring LLM inference.

        Args:
            vulnerability: The vulnerability data.
            template: The platform report template.

        Returns:
            A Report with template-filled content.
        """
        title = vulnerability.title or (
            f"Security Vulnerability: "
            f"{vulnerability.cve_id or vulnerability.affected_endpoint}"
        )

        description = vulnerability.description or (
            f"A {vulnerability.severity.value} severity vulnerability was "
            f"discovered at {vulnerability.affected_endpoint} using "
            f"{vulnerability.tool_source.value}."
        )

        reproduction_steps = (
            f"1. Navigate to {vulnerability.affected_endpoint}" + chr(10)
            + f"2. The vulnerability was identified by "
            + f"{vulnerability.tool_source.value}" + chr(10)
            + f"3. Evidence: "
            + f"{vulnerability.evidence or 'See attached tool output'}"
        )

        impact = (
            f"This {vulnerability.severity.value} severity issue affects "
            f"{vulnerability.affected_endpoint}. "
            f"CVE: {vulnerability.cve_id or 'Not assigned'}."
        )

        remediation = (
            "Please review the affected endpoint and apply appropriate "
            "security patches. Consider implementing input validation and "
            "security headers as applicable."
        )

        return Report(
            vulnerability_id=vulnerability.id,
            title=title,
            description=description,
            reproduction_steps=reproduction_steps,
            impact_assessment=impact,
            remediation=remediation,
            status=ReportStatus.DRAFT,
            generated_at=datetime.utcnow(),
        )

    async def _evaluate_quality(self, llm_response: str) -> float:
        """Evaluate the quality of an LLM-generated report.

        Simple heuristic quality scoring based on:
        - Response length (too short = low quality)
        - Presence of key sections
        - Coherence indicators

        Args:
            llm_response: The raw LLM output string.

        Returns:
            Quality score between 0.0 and 1.0.
        """
        if not llm_response or len(llm_response.strip()) < 100:
            return 0.0

        score = 0.0
        text = llm_response.lower()

        # Length score (up to 0.3)
        length = len(llm_response)
        if length >= 500:
            score += 0.3
        elif length >= 200:
            score += 0.15

        # Section presence score (up to 0.4)
        key_indicators = [
            "description", "impact", "steps", "reproduce",
            "remediation", "fix", "evidence", "proof",
        ]
        found = sum(1 for kw in key_indicators if kw in text)
        score += min(0.4, found * 0.05)

        # Coherence indicators (up to 0.3)
        if any(c in text for c in ["1.", "2.", "3."]):
            score += 0.1  # Has numbered steps
        if "http" in text or "endpoint" in text:
            score += 0.1  # References endpoints
        if len(llm_response.split(chr(10))) > 5:
            score += 0.1  # Multi-line structured

        return min(1.0, score)

    def _parse_llm_response(
        self,
        llm_response: str,
        vulnerability: Vulnerability,
        program: BountyProgram,
        cvss_result: CvssScore,
        bounty_range: BountyRange,
    ) -> Optional[Report]:
        """Parse LLM response into a Report dataclass.

        Args:
            llm_response: Raw LLM output text.
            vulnerability: Source vulnerability.
            program: Target bounty program.
            cvss_result: Calculated CVSS score.
            bounty_range: Estimated bounty range.

        Returns:
            Report instance or None if parsing fails.
        """
        try:
            lines = llm_response.strip().split(chr(10))
            title = vulnerability.title or (
                lines[0] if lines else "Vulnerability Report"
            )

            # Split the narrative into canonical sections so the dashboard can
            # show description / reproduction / impact / remediation separately.
            sections = parse_report_sections(llm_response)
            if sections.get("_matched"):
                description = sections["description"] or llm_response
                reproduction = sections["reproduction"]
                impact = sections["impact"]
                remediation = sections["remediation"]
            else:
                # No recognizable headings: keep the whole text as description
                # (previous behaviour) rather than dropping anything.
                description = llm_response
                reproduction = impact = remediation = ""

            return Report(
                vulnerability_id=vulnerability.id,
                program_id=program.id,
                platform=program.platform,
                title=title,
                description=description,
                reproduction_steps=reproduction,
                impact_assessment=impact,
                remediation=remediation,
                cvss=cvss_result,
                estimated_bounty=bounty_range,
                status=ReportStatus.DRAFT,
                generated_at=datetime.utcnow(),
            )
        except Exception as exc:
            logger.warning("Failed to parse LLM response: %s", exc)
            return None
