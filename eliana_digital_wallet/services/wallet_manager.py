"""Wallet_Manager：封裝 Electrum daemon，管理連線、同步與伺服器備援。

- generate_address：Key_Vault unlock → Electrum 產生 BIP-84 地址 → lock
- get_balance：查詢已確認/未確認餘額
- _sync_loop：每 sync_interval_seconds 同步一次
- sync_transactions：篩選新確認交易 (>=1 confirm) 寫入 Transaction_Ledger
- _failover：伺服器清單循序切換，最多 max_failover_attempts 個節點
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Callable, Optional

from ..models.schemas import TransactionRecord, WalletBalance, WalletConfig
from .electrum_client import ElectrumDaemon, is_valid_bech32_address
from .key_vault import KeyVault
from .transaction_ledger import TransactionLedger

# satoshi 與 BTC 換算
_SAT_PER_BTC = 100_000_000


class WalletManagerError(Exception):
    """Wallet_Manager 基礎例外。"""


class AllServersUnreachableError(WalletManagerError):
    """所有 Electrum 伺服器皆不可達。"""


class InvalidAddressError(WalletManagerError):
    """產生的地址格式無效。"""


class WalletManager:
    def __init__(
        self,
        daemon: ElectrumDaemon,
        key_vault: KeyVault,
        ledger: TransactionLedger,
        config: WalletConfig,
        master_password: Optional[str] = None,
        notify_callback: Optional[Callable[[str], None]] = None,
    ):
        self.daemon = daemon
        self.key_vault = key_vault
        self.ledger = ledger
        self.config = config
        self._master_password = master_password
        self._notify_callback = notify_callback
        self._current_server_index = 0
        self._sync_task: Optional[asyncio.Task] = None
        self._running = False
        # 記錄已處理過的 txid，避免重複通知
        self._seen_txids: set[str] = set()

    # ----- 生命週期 ------------------------------------------------------- #
    async def start(self) -> None:
        """連線至 Electrum 伺服器並啟動背景同步循環。"""
        connected = await self._connect_with_failover()
        if not connected:
            raise AllServersUnreachableError("無法連線至任何 Electrum 伺服器")
        self._running = True
        self._sync_task = asyncio.create_task(self._sync_loop())

    async def stop(self) -> None:
        """停止同步循環。"""
        self._running = False
        if self._sync_task is not None:
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass
            self._sync_task = None

    # ----- 地址產生 ------------------------------------------------------- #
    async def generate_address(self) -> str:
        """產生 BIP-84 Native SegWit 地址。

        前綴依設定的 network 而定：testnet -> tb1q，mainnet -> bc1q。
        流程：unlock → createnewaddress → 驗證格式 → lock。
        """
        unlocked = False
        try:
            if self._master_password is not None:
                await self.key_vault.unlock(self._master_password)
                unlocked = True
            address = await self.daemon.create_new_address()
            if not self._is_bip84_address(address):
                raise InvalidAddressError(f"非有效的 BIP-84 地址: {address}")
            return address
        finally:
            if unlocked:
                await self.key_vault.lock()

    def _expected_hrp_prefixes(self) -> tuple[str, ...]:
        """依 network 回傳可接受的 BIP-84 地址前綴。

        不寫死：testnet 接受 tb1q、mainnet 接受 bc1q。未知/未設定時兩者
        皆接受（寬鬆），但實際網路由 daemon 的 network 鎖定把關。
        """
        network = str(getattr(self.config, "network", "") or "").lower()
        if network == "mainnet":
            return ("bc1q",)
        if network == "testnet":
            return ("tb1q",)
        return ("tb1q", "bc1q")

    def _is_bip84_address(self, address: str) -> bool:
        """BIP-84 Native SegWit：network 對應前綴 + 有效 bech32 編碼。"""
        if not any(address.startswith(p) for p in self._expected_hrp_prefixes()):
            return False
        return is_valid_bech32_address(address)

    # ----- 餘額 ----------------------------------------------------------- #
    async def get_balance(self) -> WalletBalance:
        raw = await self.daemon.get_balance()
        confirmed_sat = int(raw.get("confirmed", 0))
        unconfirmed_sat = int(raw.get("unconfirmed", 0))
        return WalletBalance(
            confirmed_btc=confirmed_sat / _SAT_PER_BTC,
            unconfirmed_btc=unconfirmed_sat / _SAT_PER_BTC,
            confirmed_sat=confirmed_sat,
            unconfirmed_sat=unconfirmed_sat,
        )

    # ----- 同步 ----------------------------------------------------------- #
    async def sync_transactions(self) -> list[TransactionRecord]:
        """同步新確認交易 (>=1 confirm)，寫入 Transaction_Ledger。"""
        try:
            txs = await self.daemon.list_transactions()
        except Exception:  # noqa: BLE001 - 連線問題觸發備援
            if not await self._failover():
                return []
            txs = await self.daemon.list_transactions()

        new_records: list[TransactionRecord] = []
        for tx in txs:
            if int(tx.get("confirmations", 0)) < 1:
                continue  # 未確認，跳過
            txid = tx.get("txid", "")
            if not txid or txid in self._seen_txids:
                continue
            amount_sat = int(tx.get("amount_sat", 0))
            record = TransactionRecord(
                txid=txid,
                amount_btc=amount_sat / _SAT_PER_BTC,
                amount_sat=amount_sat,
                address=tx.get("address", ""),
                confirmed_at=self._parse_ts(tx.get("timestamp")),
            )
            await self.ledger.record_transaction(record)
            self._seen_txids.add(txid)
            new_records.append(record)
            self._notify(f"新入帳交易確認: {txid} ({record.amount_btc} BTC)")
        return new_records

    async def _sync_loop(self) -> None:
        """背景同步循環，每 sync_interval_seconds 執行一次。"""
        while self._running:
            try:
                await self.sync_transactions()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - 單次同步失敗不中斷循環
                pass
            await asyncio.sleep(self.config.sync_interval_seconds)

    # ----- 伺服器備援 ----------------------------------------------------- #
    async def _connect_with_failover(self) -> bool:
        """從當前伺服器開始嘗試連線，失敗則備援。"""
        servers = self.config.electrum_servers
        if not servers:
            return False
        if await self._try_connect(servers[self._current_server_index]):
            return True
        return await self._failover()

    async def _failover(self) -> bool:
        """循序切換至下一個備用節點，最多嘗試 max_failover_attempts 個。

        依序不重複；全部失敗回傳 False（記錄錯誤等待下次同步）。
        """
        servers = self.config.electrum_servers
        max_attempts = min(self.config.max_failover_attempts, len(servers))
        for _ in range(max_attempts):
            self._current_server_index = (
                self._current_server_index + 1
            ) % len(servers)
            server = servers[self._current_server_index]
            if await self._try_connect(server):
                self._notify(f"已備援切換至伺服器: {server}")
                return True
        self._notify("所有 Electrum 伺服器備援皆失敗，等待下次同步")
        return False

    async def _try_connect(self, server: str) -> bool:
        try:
            return await self.daemon.connect(server)
        except Exception:  # noqa: BLE001
            return False

    # ----- helper --------------------------------------------------------- #
    @staticmethod
    def _parse_ts(ts) -> datetime:
        if ts is None:
            return datetime.now(timezone.utc)
        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts)
            except ValueError:
                return datetime.now(timezone.utc)
        return datetime.now(timezone.utc)

    def _notify(self, message: str) -> None:
        if self._notify_callback is not None:
            try:
                self._notify_callback(message)
            except Exception:  # noqa: BLE001
                pass
