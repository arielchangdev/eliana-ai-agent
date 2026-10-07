"""Bounty module FastAPI endpoints.

Provides crawl management, scan management, authorization management,
and report management REST API.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.bounty.authorization import AuthorizationGate
from app.bounty.crawler import BountyCrawler
from app.bounty.database import get_bounty_db
from app.bounty.enums import (
    AuthStatus,
    PlatformType,
    ReportStatus,
    ScanStatus,
    ScanTool,
    TargetType,
)
from app.bounty.models import (
    BountyProgram,
    ScanOperation,
    ScanProfile,
    ScanProgress,
    ScanTarget,
)
from app.bounty.reporter import ReportGenerator, should_generate_report
from app.bounty.scanner import ScanEngine, select_profile

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/bounty", tags=["bounty"])



# ============================================================
# Pydantic request/response schemas
# ============================================================


class CrawlResponse(BaseModel):
    """Response for crawl trigger."""

    status: str
    message: str
    task_id: str


class BountyProgramResponse(BaseModel):
    """Bounty program response model."""

    id: str
    platform: str
    platform_program_id: str
    name: str
    organization: str
    domains: list[str]
    scope_in: list[str]
    scope_out: list[str]
    allowed_test_types: list[str]
    bounty_range_low: float
    bounty_range_high: float
    trust_score: float
    trust_level: str
    active_since: Optional[str] = None
    public_reports_count: int
    has_legal_terms: bool
    whois_verified: bool
    crawled_at: str
    updated_at: str


class AuthRequestResponse(BaseModel):
    """Authorization request response model."""

    id: str
    operation_id: str
    program_id: str
    target_url: str
    scan_types: list[str]
    status: str
    requested_at: str
    decided_at: Optional[str] = None
    expires_at: Optional[str] = None
    is_batch: bool = False


class AuthDecisionResponse(BaseModel):
    """Authorization decision response model."""

    operation_id: str
    status: str
    decided_at: Optional[str] = None
    reason: str = ""


class BatchAuthRequest(BaseModel):
    """Batch authorization request model."""

    program_id: str
    scan_types: list[str]
    validity_days: int = Field(default=7, ge=1)


class BatchAuthResponse(BaseModel):
    """Batch authorization response model."""

    id: str
    program_id: str
    scan_types: list[str]
    granted_at: str
    expires_at: str
    granted_by: str


class StartScanRequest(BaseModel):
    """Request body for starting a new scan."""

    target_url: str = Field(..., description="Target URL to scan")
    target_type: str = Field(
        default="web_app",
        description="Target type: web_app, network_service, or database_endpoint",
    )
    program_id: str = Field(..., description="Associated bounty program ID")
    port: Optional[int] = Field(default=None, description="Optional port number")


class ScanResponse(BaseModel):
    """Response returned when a scan is started."""

    scan_id: str
    status: str
    message: str


class ScanProgressResponse(BaseModel):
    """Response for scan progress queries."""

    scan_id: str
    percent_complete: float
    vulnerabilities_found: int
    estimated_remaining_seconds: float
    current_tool: Optional[str] = None
    status: str


class VulnerabilityResponse(BaseModel):
    """Vulnerability entry in scan results."""

    id: str
    cve_id: Optional[str] = None
    severity: str
    title: str
    description: str
    affected_endpoint: str
    evidence: str
    tool_source: str
    discovered_at: str


class ScanResultResponse(BaseModel):
    """Response for scan results queries."""

    scan_id: str
    status: str
    target_url: str
    target_type: str
    vulnerabilities: list[VulnerabilityResponse] = []
    tools_used: list[str] = []
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Singletons and in-memory state
# ---------------------------------------------------------------------------

_scan_engine: Optional[ScanEngine] = None
_authorization_gate_singleton: Optional[AuthorizationGate] = None

_scan_tasks: dict[str, asyncio.Task] = {}
_scan_results: dict[str, dict] = {}
_scan_statuses: dict[str, ScanStatus] = {}


def get_scan_engine() -> ScanEngine:
    """Get or create the ScanEngine singleton."""
    global _scan_engine
    if _scan_engine is None:
        _scan_engine = ScanEngine()
    return _scan_engine


def _get_authorization_gate() -> AuthorizationGate:
    """Get or create the AuthorizationGate singleton."""
    global _authorization_gate_singleton
    if _authorization_gate_singleton is None:
        _authorization_gate_singleton = AuthorizationGate()
    return _authorization_gate_singleton


# ============================================================
# Crawl management endpoints (Task 8.1)
# Requirements: 1.1, 5.5
# ============================================================


async def _run_crawl_task(task_id: str, platform: Optional[str] = None) -> None:
    """Background task to run the crawl operation."""
    crawler = BountyCrawler()
    try:
        if platform:
            platform_enum = PlatformType(platform)
            programs = await crawler.crawl_platform(platform_enum)
        else:
            programs = await crawler.crawl_all_platforms()

        db = await get_bounty_db()
        try:
            for program in programs:
                program.trust_score = crawler.calculate_trust_score(program)
                await db.execute(
                    """INSERT OR REPLACE INTO bounty_programs
                       (id, platform, platform_program_id, name, organization,
                        domains, scope_in, scope_out, allowed_test_types,
                        bounty_range_low, bounty_range_high, trust_score,
                        trust_level, active_since, public_reports_count,
                        has_legal_terms, whois_verified, crawled_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        program.id,
                        program.platform.value,
                        program.platform_program_id,
                        program.name,
                        program.organization,
                        json.dumps(program.domains),
                        json.dumps(program.scope_in),
                        json.dumps(program.scope_out),
                        json.dumps(program.allowed_test_types),
                        program.bounty_range_low,
                        program.bounty_range_high,
                        program.trust_score,
                        program.trust_level.value,
                        program.active_since.isoformat() if program.active_since else None,
                        program.public_reports_count,
                        1 if program.has_legal_terms else 0,
                        1 if program.whois_verified else 0,
                        program.crawled_at.isoformat(),
                        program.updated_at.isoformat(),
                    ),
                )
            await db.commit()
        finally:
            await db.close()

        logger.info("Crawl task %s completed: %d programs found", task_id, len(programs))
    except Exception as e:
        logger.error("Crawl task %s failed: %s", task_id, str(e))


@router.post("/crawl", response_model=CrawlResponse, status_code=status.HTTP_202_ACCEPTED)
async def trigger_crawl(
    background_tasks: BackgroundTasks,
    platform: Optional[str] = Query(default=None, description="Specific platform to crawl"),
) -> CrawlResponse:
    """Trigger a crawl of Bug Bounty platforms.

    Launches crawl_all_platforms() asynchronously as a background task.
    If a specific platform is provided, only that platform is crawled.

    Requirements: 1.1, 5.5
    """
    if platform is not None:
        try:
            PlatformType(platform)
        except ValueError:
            valid_platforms = [p.value for p in PlatformType]
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid platform: {platform}. Valid platforms: {valid_platforms}",
            )

    task_id = str(uuid.uuid4())
    background_tasks.add_task(_run_crawl_task, task_id, platform)

    message = (
        f"Crawl started for platform: {platform}"
        if platform
        else "Crawl started for all platforms"
    )
    return CrawlResponse(status="started", message=message, task_id=task_id)


@router.get("/programs", response_model=list[BountyProgramResponse])
async def list_programs(
    min_trust_score: float = Query(
        default=0.0, ge=0.0, le=1.0, description="Minimum trust score filter"
    ),
) -> list[BountyProgramResponse]:
    """List all bounty programs, optionally filtered by minimum trust score.

    Requirements: 1.1, 5.5
    """
    db = await get_bounty_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM bounty_programs WHERE trust_score >= ? "
            "ORDER BY trust_score DESC",
            (min_trust_score,),
        )
        rows = await cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
    finally:
        await db.close()

    results = []
    for row in rows:
        row_dict = dict(zip(columns, row))
        results.append(_row_to_program_response(row_dict))
    return results


@router.get("/programs/{program_id}", response_model=BountyProgramResponse)
async def get_program(program_id: str) -> BountyProgramResponse:
    """Get a single bounty program by ID.

    Returns 404 if the program is not found.

    Requirements: 1.1, 5.5
    """
    db = await get_bounty_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM bounty_programs WHERE id = ?",
            (program_id,),
        )
        row = await cursor.fetchone()

        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Program not found: {program_id}",
            )

        columns = [desc[0] for desc in cursor.description]
    finally:
        await db.close()

    row_dict = dict(zip(columns, row))
    return _row_to_program_response(row_dict)


def _row_to_program_response(row_dict: dict) -> BountyProgramResponse:
    """Convert a database row dict to BountyProgramResponse."""
    return BountyProgramResponse(
        id=row_dict["id"],
        platform=row_dict["platform"],
        platform_program_id=row_dict["platform_program_id"],
        name=row_dict["name"],
        organization=row_dict["organization"],
        domains=json.loads(row_dict["domains"]) if row_dict["domains"] else [],
        scope_in=json.loads(row_dict["scope_in"]) if row_dict["scope_in"] else [],
        scope_out=json.loads(row_dict["scope_out"]) if row_dict["scope_out"] else [],
        allowed_test_types=(
            json.loads(row_dict["allowed_test_types"])
            if row_dict["allowed_test_types"]
            else []
        ),
        bounty_range_low=row_dict["bounty_range_low"],
        bounty_range_high=row_dict["bounty_range_high"],
        trust_score=row_dict["trust_score"],
        trust_level=row_dict["trust_level"],
        active_since=row_dict["active_since"],
        public_reports_count=row_dict["public_reports_count"],
        has_legal_terms=bool(row_dict["has_legal_terms"]),
        whois_verified=bool(row_dict["whois_verified"]),
        crawled_at=row_dict["crawled_at"],
        updated_at=row_dict["updated_at"],
    )


# ============================================================
# Authorization management endpoints (Task 8.3)
# Requirements: 3.1, 3.2, 3.3, 3.5
# ============================================================


@router.get("/authorizations/pending", response_model=list[AuthRequestResponse])
async def list_pending_authorizations() -> list[AuthRequestResponse]:
    """List all pending authorization requests."""
    db = await get_bounty_db()
    try:
        cursor = await db.execute(
            "SELECT id, operation_id, program_id, target_url, scan_types, "
            "status, requested_at, decided_at, expires_at, is_batch "
            "FROM authorizations WHERE status = ?",
            (AuthStatus.PENDING.value,),
        )
        rows = await cursor.fetchall()
    finally:
        await db.close()

    results = []
    for row in rows:
        (auth_id, operation_id, program_id, target_url, scan_types_json,
         auth_status, requested_at, decided_at, expires_at, is_batch) = row
        results.append(
            AuthRequestResponse(
                id=auth_id,
                operation_id=operation_id,
                program_id=program_id,
                target_url=target_url,
                scan_types=json.loads(scan_types_json) if scan_types_json else [],
                status=auth_status,
                requested_at=requested_at,
                decided_at=decided_at,
                expires_at=expires_at,
                is_batch=bool(is_batch),
            )
        )
    return results


@router.post("/authorizations/{auth_id}/approve", response_model=AuthDecisionResponse)
async def approve_authorization(auth_id: str) -> AuthDecisionResponse:
    """Approve a pending authorization request."""
    now = datetime.now(timezone.utc)
    db = await get_bounty_db()
    try:
        cursor = await db.execute(
            "SELECT operation_id, status FROM authorizations WHERE id = ?",
            (auth_id,),
        )
        row = await cursor.fetchone()

        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Authorization {auth_id} not found",
            )

        operation_id, current_status = row
        if current_status != AuthStatus.PENDING.value:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Authorization {auth_id} is not pending (current: {current_status})",
            )

        await db.execute(
            "UPDATE authorizations SET status = ?, decided_at = ? WHERE id = ?",
            (AuthStatus.APPROVED.value, now.isoformat(), auth_id),
        )
        await db.commit()
    finally:
        await db.close()

    return AuthDecisionResponse(
        operation_id=operation_id,
        status=AuthStatus.APPROVED.value,
        decided_at=now.isoformat(),
        reason="",
    )


@router.post("/authorizations/{auth_id}/deny", response_model=AuthDecisionResponse)
async def deny_authorization(auth_id: str) -> AuthDecisionResponse:
    """Deny a pending authorization request."""
    now = datetime.now(timezone.utc)
    db = await get_bounty_db()
    try:
        cursor = await db.execute(
            "SELECT operation_id, status FROM authorizations WHERE id = ?",
            (auth_id,),
        )
        row = await cursor.fetchone()

        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Authorization {auth_id} not found",
            )

        operation_id, current_status = row
        if current_status != AuthStatus.PENDING.value:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Authorization {auth_id} is not pending (current: {current_status})",
            )

        await db.execute(
            "UPDATE authorizations SET status = ?, decided_at = ? WHERE id = ?",
            (AuthStatus.DENIED.value, now.isoformat(), auth_id),
        )
        await db.commit()
    finally:
        await db.close()

    return AuthDecisionResponse(
        operation_id=operation_id,
        status=AuthStatus.DENIED.value,
        decided_at=now.isoformat(),
        reason="",
    )


@router.post("/authorizations/batch", response_model=BatchAuthResponse, status_code=status.HTTP_201_CREATED)
async def create_batch_authorization(request: BatchAuthRequest) -> BatchAuthResponse:
    """Create a batch authorization.

    Allows the user to authorize all targets within the same BountyProgram
    scope for specified scan types. Default validity is 7 days.
    """
    scan_tools: list[ScanTool] = []
    for tool_str in request.scan_types:
        try:
            scan_tools.append(ScanTool(tool_str))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid scan type: {tool_str}. Valid: {[t.value for t in ScanTool]}",
            )

    gate = AuthorizationGate()
    batch_auth = await gate.grant_batch_authorization(
        program_id=request.program_id,
        scan_types=scan_tools,
        validity_days=request.validity_days,
    )

    return BatchAuthResponse(
        id=batch_auth.id,
        program_id=batch_auth.program_id,
        scan_types=[t.value for t in batch_auth.scan_types],
        granted_at=batch_auth.granted_at.isoformat(),
        expires_at=batch_auth.expires_at.isoformat(),
        granted_by=batch_auth.granted_by,
    )


# ============================================================
# Scan management endpoints (Task 8.2)
# Requirements: 2.1, 2.3
# ============================================================


@router.post("/scans", response_model=ScanResponse, status_code=202)
async def start_scan(request: StartScanRequest) -> ScanResponse:
    """Start a new vulnerability scan.

    Checks authorization via AuthorizationGate before launching the scan.
    Returns 202 Accepted with a scan_id for tracking progress.
    """
    try:
        target_type = TargetType(request.target_type)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid target_type: {request.target_type}. "
            f"Must be one of: web_app, network_service, database_endpoint",
        )

    scan_target = ScanTarget(
        id=str(uuid.uuid4()),
        program_id=request.program_id,
        target_url=request.target_url,
        target_type=target_type,
        port=request.port,
    )

    profile = select_profile(scan_target)

    operation = ScanOperation(
        id=str(uuid.uuid4()),
        target=scan_target,
        profile=profile,
        program_id=request.program_id,
        requested_at=datetime.now(timezone.utc),
    )

    gate = _get_authorization_gate()
    batch_auth = await gate.check_batch_authorization(operation)

    if batch_auth is None:
        auth_decision = await gate.request_authorization(operation)
        if auth_decision.status == AuthStatus.DENIED:
            raise HTTPException(status_code=403, detail="Scan authorization denied by operator.")
        if auth_decision.status == AuthStatus.PENDING:
            logger.info("Scan authorization pending, scan accepted: %s", operation.id)

    scan_id = str(uuid.uuid4())
    _scan_statuses[scan_id] = ScanStatus.RUNNING

    engine = get_scan_engine()
    task = asyncio.create_task(_run_scan(scan_id, engine, scan_target, profile))
    _scan_tasks[scan_id] = task

    logger.info("Scan %s started for target %s", scan_id, request.target_url)

    return ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.RUNNING.value,
        message=f"Scan started for {request.target_url}",
    )


@router.get("/scans/{scan_id}/progress", response_model=ScanProgressResponse)
async def get_scan_progress(scan_id: str) -> ScanProgressResponse:
    """Get the current progress of a running scan."""
    if scan_id not in _scan_statuses and scan_id not in _scan_results:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    engine = get_scan_engine()
    progress = engine.get_progress(scan_id)
    scan_status = _scan_statuses.get(scan_id, ScanStatus.QUEUED)

    if progress is not None:
        return ScanProgressResponse(
            scan_id=scan_id,
            percent_complete=progress.percent_complete,
            vulnerabilities_found=progress.vulnerabilities_found,
            estimated_remaining_seconds=progress.estimated_remaining_seconds,
            current_tool=progress.current_tool.value if progress.current_tool else None,
            status=scan_status.value,
        )

    return ScanProgressResponse(
        scan_id=scan_id,
        percent_complete=0.0,
        vulnerabilities_found=0,
        estimated_remaining_seconds=0.0,
        current_tool=None,
        status=scan_status.value,
    )


@router.get("/scans/{scan_id}/results", response_model=ScanResultResponse)
async def get_scan_results(scan_id: str) -> ScanResultResponse:
    """Get the results of a completed scan."""
    if scan_id not in _scan_statuses and scan_id not in _scan_results:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    scan_status = _scan_statuses.get(scan_id, ScanStatus.QUEUED)

    if scan_id in _scan_results:
        return ScanResultResponse(**_scan_results[scan_id])

    return ScanResultResponse(
        scan_id=scan_id,
        status=scan_status.value,
        target_url="",
        target_type="",
    )


# ---------------------------------------------------------------------------
# Background scan execution
# ---------------------------------------------------------------------------


async def _run_scan(
    scan_id: str,
    engine: ScanEngine,
    target: ScanTarget,
    profile: ScanProfile,
) -> None:
    """Execute scan in background, store results, and auto-generate reports.

    Full end-to-end flow:
    1. AuthorizationGate check is done before this function is called (in start_scan)
    2. ScanEngine executes the scan
    3. For each vulnerability with severity >= MEDIUM, ReportGenerator generates a report

    Requirements: 1.2, 2.1, 3.1, 4.1
    """
    try:
        result = await engine.execute_scan(target, profile)

        vulnerabilities = [
            VulnerabilityResponse(
                id=v.id,
                cve_id=v.cve_id,
                severity=v.severity.value,
                title=v.title,
                description=v.description,
                affected_endpoint=v.affected_endpoint,
                evidence=v.evidence,
                tool_source=v.tool_source.value,
                discovered_at=v.discovered_at.isoformat(),
            )
            for v in result.vulnerabilities
        ]

        _scan_results[scan_id] = ScanResultResponse(
            scan_id=scan_id,
            status=result.status.value,
            target_url=target.target_url,
            target_type=target.target_type.value,
            vulnerabilities=vulnerabilities,
            tools_used=[t.value for t in result.tools_used],
            started_at=result.started_at.isoformat() if result.started_at else None,
            completed_at=result.completed_at.isoformat() if result.completed_at else None,
            duration_seconds=result.duration_seconds,
        ).model_dump()

        _scan_statuses[scan_id] = result.status
        logger.info("Scan %s completed with status %s", scan_id, result.status.value)

        # Auto-generate reports for medium+ severity vulnerabilities (Requirement 4.1)
        await _auto_generate_reports(target.program_id, result.vulnerabilities)

    except Exception as e:
        logger.error("Scan %s failed: %s", scan_id, str(e))
        _scan_statuses[scan_id] = ScanStatus.FAILED
        _scan_results[scan_id] = ScanResultResponse(
            scan_id=scan_id,
            status=ScanStatus.FAILED.value,
            target_url=target.target_url,
            target_type=target.target_type.value,
        ).model_dump()


# ---------------------------------------------------------------------------
# Auto report generation for medium+ vulnerabilities (Task 8.5)
# Requirements: 4.1
# ---------------------------------------------------------------------------


async def _auto_generate_reports(
    program_id: str, vulnerabilities: list,
) -> None:
    """Auto-generate reports for vulnerabilities with severity >= MEDIUM.

    For each vulnerability that passes the should_generate_report threshold
    (MEDIUM, HIGH, CRITICAL), use ReportGenerator to create a report draft
    and persist it to the database.

    Requirements: 4.1
    """
    reportable = [v for v in vulnerabilities if should_generate_report(v)]
    if not reportable:
        return

    # Fetch the BountyProgram from DB to pass to report generator
    program = await _fetch_program(program_id)
    if program is None:
        logger.warning(
            "Cannot generate reports: program %s not found in DB", program_id
        )
        return

    report_gen = ReportGenerator()

    for vuln in reportable:
        try:
            report = await report_gen.generate_report(vuln, program)
            await _persist_report(report)
            logger.info(
                "Auto-generated report %s for vulnerability %s (severity=%s)",
                report.id,
                vuln.id,
                vuln.severity.value,
            )
        except Exception as e:
            logger.error(
                "Failed to generate report for vulnerability %s: %s",
                vuln.id,
                str(e),
            )


async def _fetch_program(program_id: str) -> Optional[BountyProgram]:
    """Fetch a BountyProgram from the database by ID."""
    db = await get_bounty_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM bounty_programs WHERE id = ?", (program_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        columns = [desc[0] for desc in cursor.description]
        row_dict = dict(zip(columns, row))

        from app.bounty.enums import TrustLevel

        return BountyProgram(
            id=row_dict["id"],
            platform=PlatformType(row_dict["platform"]),
            platform_program_id=row_dict["platform_program_id"],
            name=row_dict["name"],
            organization=row_dict.get("organization", ""),
            domains=json.loads(row_dict["domains"]) if row_dict["domains"] else [],
            scope_in=json.loads(row_dict["scope_in"]) if row_dict["scope_in"] else [],
            scope_out=json.loads(row_dict["scope_out"]) if row_dict["scope_out"] else [],
            allowed_test_types=(
                json.loads(row_dict["allowed_test_types"])
                if row_dict["allowed_test_types"]
                else []
            ),
            bounty_range_low=row_dict["bounty_range_low"],
            bounty_range_high=row_dict["bounty_range_high"],
            trust_score=row_dict["trust_score"],
            trust_level=TrustLevel(row_dict["trust_level"]),
            active_since=None,
            public_reports_count=row_dict["public_reports_count"],
            has_legal_terms=bool(row_dict["has_legal_terms"]),
            whois_verified=bool(row_dict["whois_verified"]),
        )
    finally:
        await db.close()


async def _persist_report(report) -> None:
    """Persist a generated Report to the database."""
    db = await get_bounty_db()
    try:
        await db.execute(
            """INSERT INTO reports
               (id, vulnerability_id, program_id, platform, title,
                description, reproduction_steps, impact_assessment,
                remediation, cvss_score, cvss_vector,
                estimated_bounty_min, estimated_bounty_max,
                status, llm_quality_score, generated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                report.id,
                report.vulnerability_id,
                report.program_id,
                report.platform.value,
                report.title,
                report.description,
                report.reproduction_steps,
                report.impact_assessment,
                report.remediation,
                report.cvss.base_score,
                report.cvss.vector_string,
                report.estimated_bounty.min_usd,
                report.estimated_bounty.max_usd,
                report.status.value,
                report.llm_quality_score,
                report.generated_at.isoformat(),
            ),
        )
        await db.commit()
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Task_Scheduler integration for periodic crawl (Task 8.5)
# Requirements: 1.2
# ---------------------------------------------------------------------------

# Default crawl interval: 24 hours (86400 seconds)
_CRAWL_INTERVAL_SECONDS: int = 86400


async def _scheduled_crawl_task() -> None:
    """Coroutine executed by Task_Scheduler for periodic crawl.

    Runs crawl_all_platforms and persists results to the database.
    This is the handler registered with Task_Scheduler for daily crawl.
    """
    await _run_crawl_task(task_id=str(uuid.uuid4()))


def register_scheduled_crawl(scheduler=None) -> dict:
    """Register the periodic crawl task with Task_Scheduler.

    Integrates with eliana-core-infra Task_Scheduler to schedule
    daily crawl of all Bug Bounty platforms.

    Args:
        scheduler: Task_Scheduler instance from eliana-core-infra.
                   If None, returns the configuration dict without registering.

    Returns:
        Configuration dict with task registration details.

    Requirements: 1.2
    """
    config = {
        "task_name": "bounty_crawl_all_platforms",
        "handler": _scheduled_crawl_task,
        "interval_seconds": _CRAWL_INTERVAL_SECONDS,
        "description": "Periodic crawl of Bug Bounty platforms (daily)",
    }

    if scheduler is not None:
        try:
            # Task_Scheduler.register_task(name, coro, interval_seconds)
            scheduler.register_task(
                config["task_name"],
                config["handler"],
                config["interval_seconds"],
            )
            logger.info(
                "Registered scheduled crawl with Task_Scheduler (interval=%ds)",
                _CRAWL_INTERVAL_SECONDS,
            )
        except (AttributeError, TypeError) as e:
            logger.warning(
                "Task_Scheduler not available, crawl schedule deferred: %s", e
            )

    return config

# ============================================================
# Pydantic request/response schemas for report endpoints (Task 8.4)
# ============================================================


class ReportSummaryResponse(BaseModel):
    """Report summary response model for list endpoint."""

    id: str
    vulnerability_id: str
    program_id: str
    platform: str
    title: str
    status: str
    cvss_score: float = 0.0
    estimated_bounty_min: float = 0.0
    estimated_bounty_max: float = 0.0
    llm_quality_score: float = 0.0
    generated_at: str


class PaginatedReportsResponse(BaseModel):
    """Paginated response for report listing."""

    items: list[ReportSummaryResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class ReportDetailResponse(BaseModel):
    """Full report detail response model."""

    id: str
    vulnerability_id: str
    program_id: str
    platform: str
    title: str
    description: str = ""
    reproduction_steps: str = ""
    impact_assessment: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    estimated_bounty_min: float = 0.0
    estimated_bounty_max: float = 0.0
    status: str
    llm_quality_score: float = 0.0
    generated_at: str


# ============================================================
# Report management API endpoints (Task 8.4)
# Requirements: 4.4
# ============================================================


@router.get("/reports", response_model=PaginatedReportsResponse)
async def list_reports(
    report_status: Optional[str] = Query(
        default=None, description="Filter by report status (draft, reviewed, submitted)"
    ),
    page: int = Query(default=1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
) -> PaginatedReportsResponse:
    """List all reports with pagination, optionally filtered by status.

    Args:
        report_status: Optional report status filter (draft, reviewed, submitted).
        page: Page number (1-based, default 1).
        page_size: Number of items per page (default 20, max 100).

    Returns:
        Paginated report summaries ordered by generated_at descending.
    """
    db = await get_bounty_db()
    try:
        params: list = []
        where_clause = ""

        if report_status is not None:
            # Validate that status is a valid ReportStatus value
            try:
                ReportStatus(report_status)
            except ValueError:
                valid = [s.value for s in ReportStatus]
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid status. Valid values: {valid}",
                )
            where_clause = "WHERE status = ?"
            params.append(report_status)

        # Get total count
        count_query = f"SELECT COUNT(*) FROM reports {where_clause}"
        cursor = await db.execute(count_query, params)
        total = (await cursor.fetchone())[0]

        # Calculate pagination
        offset = (page - 1) * page_size
        total_pages = max(1, (total + page_size - 1) // page_size)

        # Fetch paginated results
        data_query = (
            f"SELECT * FROM reports {where_clause} "
            f"ORDER BY generated_at DESC LIMIT ? OFFSET ?"
        )
        cursor = await db.execute(data_query, params + [page_size, offset])
        rows = await cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]

        items = []
        for row in rows:
            report_dict = dict(zip(columns, row))
            items.append(ReportSummaryResponse(**report_dict))

        return PaginatedReportsResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )
    finally:
        await db.close()


@router.get("/reports/{report_id}", response_model=ReportDetailResponse)
async def get_report(report_id: str) -> ReportDetailResponse:
    """Get full report details by ID.

    Args:
        report_id: The report unique identifier.

    Returns:
        Complete report data.

    Raises:
        HTTPException 404: Report not found.
    """
    db = await get_bounty_db()
    try:
        cursor = await db.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
        row = await cursor.fetchone()

        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report not found: {report_id}",
            )

        columns = [desc[0] for desc in cursor.description]
        report_dict = dict(zip(columns, row))
        return ReportDetailResponse(**report_dict)
    finally:
        await db.close()


@router.post("/reports/{report_id}/approve", response_model=ReportDetailResponse)
async def approve_report(report_id: str) -> ReportDetailResponse:
    """Approve a report, transitioning status from DRAFT to REVIEWED.

    Only reports in DRAFT status can be approved. Attempting to approve
    a report in any other status returns HTTP 409 Conflict.

    Args:
        report_id: The report unique identifier.

    Returns:
        Updated report data with new status.

    Raises:
        HTTPException 404: Report not found.
        HTTPException 409: Invalid status transition (report is not in DRAFT status).
    """
    db = await get_bounty_db()
    try:
        cursor = await db.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
        row = await cursor.fetchone()

        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report not found: {report_id}",
            )

        columns = [desc[0] for desc in cursor.description]
        report_dict = dict(zip(columns, row))

        current_report_status = report_dict["status"]
        if current_report_status != ReportStatus.DRAFT.value:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Cannot approve report in '{current_report_status}' status. "
                    f"Only reports in '{ReportStatus.DRAFT.value}' status can be approved."
                ),
            )

        # Update status to REVIEWED (approved transition)
        await db.execute(
            "UPDATE reports SET status = ? WHERE id = ?",
            (ReportStatus.REVIEWED.value, report_id),
        )
        await db.commit()

        # Return updated report
        report_dict["status"] = ReportStatus.REVIEWED.value
        return ReportDetailResponse(**report_dict)
    finally:
        await db.close()
