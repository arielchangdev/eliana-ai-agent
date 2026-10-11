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


class AuthorizedScanner:
    def __init__(self, db_path: str = "data/bounty.db", scan_engine=None):
        self._db_path = db_path
        self._engine = scan_engine

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
        return await self._engine.execute_scan(target, profile)