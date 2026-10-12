"""Authorized scan orchestration — the ONLY entry point for running scans.

Enforces, BEFORE any tool touches the weapon host:
  1. target in authorized scope (is_target_in_scope)
  2. an explicit, non-expired human authorization record exists in bounty.db

If either check fails, the scan is refused, audited, and NO tool is executed.
This is a hard, non-bypassable gate — interactive /authorize in Telegram is just
how an authorization record gets created; it never replaces this gate.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)


class ScanNotAuthorized(Exception):
    """Raised when a scan is attempted against an out-of-scope or unauthorized target."""


class OllamaReportLLM:
    """Adapter: expose a `.generate(prompt) -> str` for the report generator,
    backed by the local Ollama model.

    The report generator treats the return value as a plain string, but
    LocalLLM.generate() returns an LLMResponse — this adapter unwraps `.text`.
    Report narrative only; the CVSS SCORE is always computed by the cvss
    formula in reporter.calculate_cvss(), never by the LLM. Runs on the local
    model (default llama3.2:3b) so it stays $0 and does not consume the cloud
    conversation quota, and sensitive scan data never leaves the host.
    """

    def __init__(self, local_llm=None, model: Optional[str] = None):
        self._llm = local_llm
        import os
        self._model = model or os.environ.get(
            "ELIANA_REPORT__MODEL", "llama3.2:3b")

    async def generate(self, prompt: str) -> str:
        if self._llm is None:
            return ""
        resp = await self._llm.generate(prompt, model=self._model)
        # LocalLLM returns LLMResponse(text=...); tolerate a plain str too.
        return getattr(resp, "text", resp) or ""


class AuthorizedScanner:
    def __init__(self, db_path: str = "data/bounty.db", scan_engine=None,
                 report_llm=None, assessment_memory=None):
        self._db_path = db_path
        self._engine = scan_engine
        # Optional LLM client for report narrative. None -> template-only.
        # CVSS score is ALWAYS computed by the cvss formula, never the LLM.
        self._report_llm = report_llm
        # Optional growth-loop memory: records assessment experience (findings
        # patterns / tool efficacy) so future assessments can recall. None -> off.
        self._assessment_memory = assessment_memory

    # ---- authorization record management ---- #
    def grant_authorization(self, target_url: str, program_id: str = "manual",
                            scan_types=None, validity_hours: int = 24) -> str:
        """Record an explicit human authorization (called after Telegram /authorize)."""
        auth_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=validity_hours)
        conn = sqlite3.connect(self._db_path)
        try:
            conn.execute(
                "INSERT INTO authorizations (id, operation_id, program_id, target_url,"
                " scan_types, status, requested_at, decided_at, expires_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (auth_id, auth_id, program_id, target_url,
                 json.dumps(scan_types or []), "approved",
                 now.isoformat(), now.isoformat(), expires.isoformat()),
            )
            conn.commit()
        finally:
            conn.close()
        logger.info("authorization_granted", target=target_url, expires=expires.isoformat())
        return auth_id

    def is_authorized(self, target_url: str) -> bool:
        """True iff a non-expired 'approved' authorization exists for this exact target."""
        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(self._db_path)
        try:
            cur = conn.execute(
                "SELECT COUNT(*) FROM authorizations WHERE target_url = ?"
                " AND status = 'approved' AND (expires_at IS NULL OR expires_at > ?)",
                (target_url, now),
            )
            return cur.fetchone()[0] > 0
        finally:
            conn.close()

    # ---- the hard gate ---- #
    async def scan(self, target_url: str, scope, profile):
        """Run a scan ONLY if target is in scope AND explicitly authorized."""
        from app.bounty.scanner import is_target_in_scope
        from app.bounty.models import ScanTarget
        from app.bounty.enums import TargetType

        # Normalize: is_target_in_scope uses urlparse, which needs a scheme to
        # extract hostname. Bare "example.com" -> "https://example.com".
        norm = target_url if "://" in target_url else f"https://{target_url}"
        # Gate 1: scope
        if not is_target_in_scope(norm, scope):
            logger.warning("scan_refused_out_of_scope", target=target_url)
            raise ScanNotAuthorized(f"target not in scope: {target_url}")
        # Gate 2: explicit authorization record
        if not self.is_authorized(target_url):
            logger.warning("scan_refused_unauthorized", target=target_url)
            raise ScanNotAuthorized(f"no valid authorization for: {target_url}")
        if self._engine is None:
            raise RuntimeError("scan engine not wired")

        logger.info("scan_authorized_proceeding", target=target_url)
        # Ensure nmap emits XML to stdout so parse_nmap_xml works; use the host only
        from app.bounty.enums import ScanTool
        try:
            if ScanTool.NMAP in profile.tools:
                existing = profile.args.get(ScanTool.NMAP, [])
                if not any(a in ("-oX", "-oA") for a in existing):
                    profile.args[ScanTool.NMAP] = ["-oX", "-", "-T4", "-F"] + list(existing)
        except Exception:
            pass
        # Ensure the SSH channel to the weapon host is connected before scanning
        ssh = getattr(self._engine, "_ssh", None)
        if ssh is not None:
            try:
                connected = ssh.is_connected
            except Exception:
                connected = False
            if not connected:
                logger.info("connecting_ssh_before_scan")
                await ssh.connect()
        scan_host = norm.split("://")[-1].split("/")[0]
        target = ScanTarget(program_id="manual", target_url=scan_host,
                            target_type=TargetType.WEB_APP)

        # Persistence: ScanEngine.execute_scan only writes scan/vuln records when
        # it has a db connection. build_subsystems() is sync and cannot open an
        # async aiosqlite connection, so we open one here (async context) using
        # the same bounty.db the authorization records live in, inject it into
        # the engine for the duration of the scan, then close it. If the engine
        # already has a db (e.g. real test wiring), we leave it untouched.
        if getattr(self._engine, "_db", None) is not None:
            result = await self._engine.execute_scan(target, profile)
            await self._generate_reports(result, self._engine._db)
            self._record_experience(target_url, result)
            return result

        import aiosqlite
        async with aiosqlite.connect(self._db_path) as conn:
            self._engine._db = conn
            try:
                result = await self._engine.execute_scan(target, profile)
                # Report generation on the SAME connection the scan/vuln rows
                # were written to (reports.vulnerability_id FK -> vulnerabilities).
                await self._generate_reports(result, conn)
                self._record_experience(target_url, result)
                return result
            finally:
                self._engine._db = None

    def _record_experience(self, target_url: str, result) -> None:
        """成長閉環（存）：把這次授權評估的發現模式存為可回想的經驗。
        學方法論/效能（工具、發現類型、ATT&CK 分類），不學攻擊技巧。"""
        if self._assessment_memory is None:
            return
        try:
            vulns = getattr(result, "vulnerabilities", []) or []
            tools_used = [t.value for t in getattr(result, "tools_used", [])]
            findings = [{
                "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
                "attack_technique_id": getattr(v, "attack_technique_id", None),
                "attack_technique_name": getattr(v, "attack_technique_name", None),
            } for v in vulns]
            target_type = "web_app"
            self._assessment_memory.record_assessment(
                target=target_url, target_type=target_type,
                tools_used=tools_used, findings=findings)
        except Exception as exc:
            logger.warning("record_experience_failed", error=str(exc))

    async def _ensure_manual_program(self, conn) -> None:
        """Ensure a 'manual' bounty_programs row exists so report generation
        has a program to attach to. This is NOT a real bounty program: platform
        is only used to pick a report-format template, and bounty_range is 0 so
        the bounty estimate is honestly 0 (manual scans have no real bounty)."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        await conn.execute(
            "INSERT OR IGNORE INTO bounty_programs"
            " (id, platform, platform_program_id, name, organization, domains,"
            " scope_in, scope_out, allowed_test_types, bounty_range_low,"
            " bounty_range_high, trust_score, trust_level, active_since,"
            " public_reports_count, has_legal_terms, whois_verified,"
            " crawled_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("manual", "hackerone", "manual", "Manual / Authorized Scan", "",
             "[]", "[]", "[]", "[]", 0.0, 0.0, 0.0, "suspicious", now,
             0, 0, 0, now, now),
        )
        await conn.commit()

    async def _generate_reports(self, result, conn) -> None:
        """For each MEDIUM+ finding of an authorized scan, generate a report
        (objective CVSS via formula + optional LLM narrative) and persist it.

        Honest by design: only reports findings the scan actually produced;
        INFO/LOW produce no report (should_generate_report gate). If no LLM
        client is wired, the narrative falls back to a structured template.
        """
        from app.bounty.reporter import ReportGenerator, should_generate_report

        vulns = getattr(result, "vulnerabilities", None) or []
        reportable = [v for v in vulns if should_generate_report(v)]
        if not reportable:
            logger.info("no_reportable_findings",
                        total=len(vulns), reportable=0)
            return

        await self._ensure_manual_program(conn)
        program = await self._fetch_program(conn, "manual")
        if program is None:
            logger.warning("report_skipped_no_program")
            return

        # 成長閉環-1：回想與這次發現相似的「過往評估經驗」，附進報告做脈絡
        # 參考。recall 發生在存這次經驗之前（_record_experience 在 scan 收尾
        # 更後面），所以引用的是真正的過往經驗，不會引用到自己。
        report_gen = ReportGenerator(llm_client=self._report_llm)
        for vuln in reportable:
            try:
                report = await report_gen.generate_report(vuln, program)
                if self._assessment_memory is not None:
                    try:
                        q = f"{vuln.title} {vuln.description}"
                        past = self._assessment_memory.recall_similar(q, k=2)
                        if past:
                            ref = "\n\n--- 參考過往評估經驗（回想） ---\n" + \
                                  "\n".join(f"• {p.splitlines()[0]}" for p in past)
                            report.description = (report.description or "") + ref
                    except Exception:
                        pass
                await self._persist_report(conn, report)
                logger.info("report_generated", vuln=vuln.id,
                            severity=vuln.severity.value,
                            cvss=report.cvss.base_score)
            except Exception as exc:
                logger.error("report_generation_failed",
                             vuln=getattr(vuln, "id", "?"), error=str(exc))

    async def _fetch_program(self, conn, program_id: str):
        """Load a BountyProgram from db (needed by the report generator)."""
        from app.bounty.models import BountyProgram
        from app.bounty.enums import PlatformType
        cur = await conn.execute(
            "SELECT id, platform, platform_program_id, name, organization,"
            " bounty_range_low, bounty_range_high FROM bounty_programs"
            " WHERE id = ?", (program_id,))
        row = await cur.fetchone()
        if row is None:
            return None
        return BountyProgram(
            id=row[0], platform=PlatformType(row[1]),
            platform_program_id=row[2], name=row[3], organization=row[4],
            bounty_range_low=row[5], bounty_range_high=row[6],
        )

    async def _persist_report(self, conn, report) -> None:
        """Write a generated Report to the reports table."""
        await conn.execute(
            "INSERT INTO reports"
            " (id, vulnerability_id, program_id, platform, title, description,"
            " reproduction_steps, impact_assessment, remediation, cvss_score,"
            " cvss_vector, estimated_bounty_min, estimated_bounty_max, status,"
            " llm_quality_score, generated_at, attack_technique_id,"
            " attack_technique_name, attack_tactic)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (report.id, report.vulnerability_id, report.program_id,
             report.platform.value, report.title, report.description,
             report.reproduction_steps, report.impact_assessment,
             report.remediation, float(report.cvss.base_score),
             report.cvss.vector_string, float(report.estimated_bounty.min_usd),
             float(report.estimated_bounty.max_usd), report.status.value,
             float(report.llm_quality_score), report.generated_at.isoformat(),
             getattr(report, "attack_technique_id", None),
             getattr(report, "attack_technique_name", None),
             getattr(report, "attack_tactic", None)),
        )
        await conn.commit()