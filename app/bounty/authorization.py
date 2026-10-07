"""Authorization gate module.

Implements AuthorizationGate class.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import aiosqlite

from app.bounty.database import get_bounty_db
from app.bounty.enums import AuthStatus, ScanTool
from app.bounty.errors import AuthorizationTimeoutError
from app.bounty.models import AuthDecision, BatchAuth, ScanOperation


class AuthorizationGate:
    """?????????????????????

    ????????????????????????????????
    ???????????????????
    """

    def __init__(self, db_path: str = "data/bounty.db"):
        """????????

        Args:
            db_path: SQLite ????????
        """
        self._db_path = db_path

    async def request_authorization(self, operation: ScanOperation) -> AuthDecision:
        """??????????????????????

        Args:
            operation: ?????????

        Returns:
            AuthDecision?????? PENDING?
        """
        auth_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        scan_types_json = json.dumps([tool.value for tool in operation.profile.tools])

        db = await get_bounty_db(self._db_path)
        try:
            await db.execute(
                "INSERT INTO authorizations (id, operation_id, program_id, target_url, scan_types, status, requested_at, is_batch) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    auth_id,
                    operation.id,
                    operation.program_id,
                    operation.target.target_url,
                    scan_types_json,
                    AuthStatus.PENDING.value,
                    now.isoformat(),
                    0,
                ),
            )
            await db.commit()
        finally:
            await db.close()

        return AuthDecision(
            operation_id=operation.id,
            status=AuthStatus.PENDING,
            decided_at=None,
            reason="",
        )

    async def check_batch_authorization(self, operation: ScanOperation) -> Optional[BatchAuth]:
        """??????????????????"""
        now = datetime.now(timezone.utc)
        db = await get_bounty_db(self._db_path)
        try:
            cursor = await db.execute(
                "SELECT id, program_id, scan_types, requested_at, expires_at FROM authorizations WHERE program_id = ? AND is_batch = 1 AND status = ? AND expires_at IS NOT NULL",
                (operation.program_id, AuthStatus.APPROVED.value),
            )
            rows = await cursor.fetchall()
        finally:
            await db.close()

        operation_tools = {tool.value for tool in operation.profile.tools}

        for row in rows:
            auth_id, program_id, scan_types_json, requested_at_str, expires_at_str = row
            expires_at = datetime.fromisoformat(expires_at_str)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if now >= expires_at:
                continue
            batch_scan_types = set(json.loads(scan_types_json))
            if operation_tools.issubset(batch_scan_types):
                granted_at = datetime.fromisoformat(requested_at_str)
                if granted_at.tzinfo is None:
                    granted_at = granted_at.replace(tzinfo=timezone.utc)
                return BatchAuth(
                    id=auth_id,
                    program_id=program_id,
                    scan_types=[ScanTool(t) for t in batch_scan_types],
                    granted_at=granted_at,
                    expires_at=expires_at,
                    granted_by="operator",
                )

        return None

    async def grant_batch_authorization(
        self, program_id: str, scan_types: list[ScanTool], validity_days: int = 7
    ) -> BatchAuth:
        """???????????? 7 ???"""
        auth_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=validity_days)
        scan_types_json = json.dumps([tool.value for tool in scan_types])

        db = await get_bounty_db(self._db_path)
        try:
            await db.execute(
                "INSERT INTO authorizations (id, operation_id, program_id, target_url, scan_types, status, requested_at, decided_at, expires_at, is_batch) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    auth_id,
                    "",
                    program_id,
                    "",
                    scan_types_json,
                    AuthStatus.APPROVED.value,
                    now.isoformat(),
                    now.isoformat(),
                    expires_at.isoformat(),
                    1,
                ),
            )
            await db.commit()
        finally:
            await db.close()

        return BatchAuth(
            id=auth_id,
            program_id=program_id,
            scan_types=scan_types,
            granted_at=now,
            expires_at=expires_at,
            granted_by="operator",
        )

    async def revoke_expired_authorizations(self) -> int:
        """?????????????"""
        now = datetime.now(timezone.utc)
        db = await get_bounty_db(self._db_path)
        try:
            cursor = await db.execute(
                "UPDATE authorizations SET status = ? WHERE is_batch = 1 AND status = ? AND expires_at IS NOT NULL AND expires_at < ?",
                (
                    AuthStatus.EXPIRED.value,
                    AuthStatus.APPROVED.value,
                    now.isoformat(),
                ),
            )
            count = cursor.rowcount
            await db.commit()
        finally:
            await db.close()

        return count

    async def cancel_expired_requests(self) -> int:
        """???? 24 ???????????"""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=24)
        db = await get_bounty_db(self._db_path)
        try:
            cursor = await db.execute(
                "UPDATE authorizations SET status = ? WHERE is_batch = 0 AND status = ? AND requested_at < ?",
                (
                    AuthStatus.EXPIRED.value,
                    AuthStatus.PENDING.value,
                    cutoff.isoformat(),
                ),
            )
            count = cursor.rowcount
            await db.commit()
        finally:
            await db.close()

        return count


def is_authorization_valid(auth: BatchAuth) -> bool:
    """????????????????????"""
    now = datetime.now(timezone.utc)
    expires_at = auth.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    return now < expires_at


def format_operation_summary(operation: ScanOperation) -> str:
    """???????????????????"""
    tools_str = ", ".join(tool.value for tool in operation.profile.tools)
    target_type = operation.target.target_type.value

    summary_lines = [
        "=== ???????? ===",
        f"?? URL: {operation.target.target_url}",
        f"????: {target_type}",
        f"????: {tools_str}",
        f"?? ID: {operation.program_id}",
        "========================",
    ]

    return "\n".join(summary_lines)

