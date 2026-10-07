"""FastAPI Router：錢包 REST 端點。

以 create_router(components) 工廠回傳 APIRouter，可掛載於 eliana-core-infra
的 FastAPI app。錯誤對映：
- LockedOutError → 423 Locked
- IntegrityError → 409 Conflict
- 伺服器不可達 → 503 Service Unavailable
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from ..models.schemas import LedgerFilter
from ..services.backup_engine import IntegrityError
from ..services.key_vault import LockedOutError
from ..services.wallet_manager import (
    AllServersUnreachableError,
    InvalidAddressError,
)


@dataclass
class WalletComponents:
    """錢包模組各服務的容器。"""

    wallet: Any = None
    ledger: Any = None
    asset_query: Any = None
    backup: Any = None


# --------------------------------------------------------------------------- #
# 請求 / 回應 模型
# --------------------------------------------------------------------------- #
class UpdateTransactionRequest(BaseModel):
    field: str
    new_value: str


class BackupRestoreRequest(BaseModel):
    backup_id: str
    master_password: str


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"無效的日期格式: {value}")


def create_router(components: WalletComponents) -> APIRouter:
    router = APIRouter(prefix="/wallet", tags=["wallet"])

    # ----- 10.1 錢包端點 --------------------------------------------- #
    @router.post("/address")
    async def create_address():
        if components.wallet is None:
            raise HTTPException(status_code=503, detail="Wallet 未初始化")
        try:
            address = await components.wallet.generate_address()
        except LockedOutError as e:
            raise HTTPException(status_code=423, detail=str(e))
        except InvalidAddressError as e:
            raise HTTPException(status_code=503, detail=str(e))
        except AllServersUnreachableError as e:
            raise HTTPException(status_code=503, detail=str(e))
        return {"address": address}

    @router.get("/balance")
    async def get_balance():
        if components.asset_query is None:
            raise HTTPException(status_code=503, detail="AssetQuery 未初始化")
        try:
            summary = await components.asset_query.get_balance_summary()
        except AllServersUnreachableError as e:
            raise HTTPException(status_code=503, detail=str(e))
        return summary.model_dump(mode="json")

    @router.get("/transactions")
    async def list_transactions(
        start_date: Optional[str] = Query(None),
        end_date: Optional[str] = Query(None),
        platform: Optional[str] = Query(None),
        severity: Optional[str] = Query(None),
    ):
        if components.asset_query is None:
            raise HTTPException(status_code=503, detail="AssetQuery 未初始化")
        filters = LedgerFilter(
            start_date=_parse_iso(start_date),
            end_date=_parse_iso(end_date),
            platform=platform,
            severity=severity,
        )
        records = await components.asset_query.query_transactions(filters)
        return {"transactions": [r.model_dump(mode="json") for r in records]}

    @router.put("/transactions/{txid}")
    async def update_transaction(txid: str, req: UpdateTransactionRequest):
        if components.ledger is None:
            raise HTTPException(status_code=503, detail="Ledger 未初始化")
        try:
            await components.ledger.update_field(txid, req.field, req.new_value)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        return {"updated": True, "txid": txid, "field": req.field}

    # ----- 10.2 統計與備份端點 --------------------------------------- #
    @router.get("/stats")
    async def get_stats():
        if components.asset_query is None:
            raise HTTPException(status_code=503, detail="AssetQuery 未初始化")
        stats = await components.asset_query.get_cumulative_stats()
        return stats.model_dump(mode="json")

    @router.get("/report/monthly")
    async def monthly_report(year: int, month: Optional[int] = None):
        if components.asset_query is None:
            raise HTTPException(status_code=503, detail="AssetQuery 未初始化")
        reports = await components.asset_query.generate_monthly_report(year, month)
        return {"reports": [r.model_dump(mode="json") for r in reports]}

    @router.post("/backup/run")
    async def run_backup():
        if components.backup is None:
            raise HTTPException(status_code=503, detail="Backup 未初始化")
        result = await components.backup.execute_backup()
        if not result.success:
            raise HTTPException(status_code=500, detail=result.error or "備份失敗")
        return result.model_dump(mode="json")

    @router.post("/backup/restore")
    async def restore_backup(req: BackupRestoreRequest):
        if components.backup is None:
            raise HTTPException(status_code=503, detail="Backup 未初始化")
        try:
            result = await components.backup.restore(
                req.backup_id, req.master_password
            )
        except IntegrityError as e:
            raise HTTPException(status_code=409, detail=str(e))
        except LockedOutError as e:
            raise HTTPException(status_code=423, detail=str(e))
        if not result.success:
            # 校驗不符也回 409
            if result.error and "校驗" in result.error:
                raise HTTPException(status_code=409, detail=result.error)
            raise HTTPException(status_code=400, detail=result.error or "還原失敗")
        return result.model_dump(mode="json")

    @router.get("/backup/list")
    async def list_backups():
        if components.backup is None:
            raise HTTPException(status_code=503, detail="Backup 未初始化")
        metas = await components.backup.list_backups()
        return {"backups": [m.model_dump(mode="json") for m in metas]}

    return router
