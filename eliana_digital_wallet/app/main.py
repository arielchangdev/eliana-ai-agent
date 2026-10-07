"""服務生命週期管理與元件組裝。

提供 build_components() 組裝五大服務，以及 create_app() 建立可獨立運行的
FastAPI app（含 lifespan）。整合至 eliana-core-infra 時，可改為在其 app
上呼叫 include_router(create_router(components))。
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI

from ..api.router import WalletComponents, create_router
from ..models.schemas import BackupConfig, KeyVaultConfig, WalletConfig
from ..services.asset_query_service import AssetQueryService
from ..services.backup_engine import BackupEngine
from ..services.key_vault import KeyVault
from ..services.transaction_ledger import TransactionLedger
from ..services.wallet_manager import WalletManager

logger = logging.getLogger(__name__)


async def build_components(
    daemon,
    wallet_config: WalletConfig,
    key_vault_config: KeyVaultConfig,
    backup_config: BackupConfig,
    master_password: str,
    ledger_db_path: str = "data/wallet.db",
    http_client=None,
) -> WalletComponents:
    """組裝並初始化五大服務，回傳 WalletComponents。

    daemon 為注入的 Electrum daemon 實作（整合階段接真實 daemon）。
    """
    key_vault = KeyVault(key_vault_config)
    await key_vault.initialize()

    ledger = TransactionLedger(ledger_db_path)
    await ledger.initialize()

    wallet = WalletManager(
        daemon=daemon,
        key_vault=key_vault,
        ledger=ledger,
        config=wallet_config,
        master_password=master_password,
    )

    asset_query = AssetQueryService(
        wallet=wallet, ledger=ledger, http_client=http_client
    )

    backup = BackupEngine(
        config=backup_config,
        master_password=master_password,
        source_paths=[key_vault_config.encrypted_wallet_path],
    )

    return WalletComponents(
        wallet=wallet,
        ledger=ledger,
        asset_query=asset_query,
        backup=backup,
    )


def create_app(components: WalletComponents) -> FastAPI:
    """建立獨立 FastAPI app，掛載錢包 router 並管理 wallet 同步生命週期。"""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # 啟動：啟動錢包同步（若 daemon 就緒）
        started = False
        if components.wallet is not None:
            try:
                await components.wallet.start()
                started = True
                logger.info("Wallet_Manager 同步已啟動")
            except Exception as exc:  # noqa: BLE001 - daemon 未就緒不阻斷 API
                logger.warning("Wallet_Manager 啟動失敗（將於稍後重試）: %s", exc)
        app.state.wallet_components = components
        yield
        # 關閉：停止同步、關閉 ledger
        if started and components.wallet is not None:
            await components.wallet.stop()
        if components.ledger is not None:
            await components.ledger.close()
        logger.info("錢包模組已關閉")

    app = FastAPI(
        title="Eliana Digital Wallet",
        description="Eliana 數位錢包模組 REST API",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(create_router(components))
    return app
