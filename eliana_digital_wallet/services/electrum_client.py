"""Electrum daemon 介面（Protocol）與 bech32 工具。

以 Protocol 定義注入式介面，讓 WalletManager 不直接相依實際 Electrum
daemon，便於測試以 mock 替代。真實實作 HttpElectrumDaemon 接 Electrum
JSON-RPC（預設 testnet）。
"""
from __future__ import annotations

import os
from typing import Any, Optional, Protocol, runtime_checkable


@runtime_checkable
class ElectrumDaemon(Protocol):
    """Electrum daemon 最小介面。"""

    async def connect(self, server: str) -> bool:
        """連線至指定 Electrum 伺服器，成功回傳 True。"""
        ...

    async def create_new_address(self) -> str:
        """產生新的 BIP-84 接收地址。"""
        ...

    async def get_balance(self) -> dict:
        """回傳餘額，格式 {"confirmed": sat, "unconfirmed": sat}。"""
        ...

    async def list_transactions(self) -> list[dict]:
        """回傳交易列表。"""
        ...


# --------------------------------------------------------------------------- #
# 真實實作：連 Electrum JSON-RPC daemon
# --------------------------------------------------------------------------- #
class ElectrumRpcError(Exception):
    """Electrum JSON-RPC 呼叫失敗。"""


class HttpElectrumDaemon:
    """ElectrumDaemon 的真實實作，透過 JSON-RPC 連本機 Electrum daemon。

    連線參數全走環境變數（不寫死 host/帳密）：
      ELIANA_WALLET__ELECTRUM_RPC_URL  (預設 http://127.0.0.1:7777)
      ELIANA_WALLET__RPC_USER          (預設 user)
      ELIANA_WALLET__RPC_PASSWORD      (必填；daemon 的 rpcpassword)
      ELIANA_WALLET__NETWORK           (預設 testnet；安全預設不碰 mainnet)

    網路鎖定：預設 testnet；啟動時以 getinfo 核對 daemon 實際 network 與
    期望一致，不一致直接拒絕（避免誤連 mainnet）。
    """

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        rpc_user: Optional[str] = None,
        rpc_password: Optional[str] = None,
        network: Optional[str] = None,
    ) -> None:
        self._url = rpc_url or os.environ.get(
            "ELIANA_WALLET__ELECTRUM_RPC_URL", "http://127.0.0.1:7777")
        self._user = rpc_user or os.environ.get(
            "ELIANA_WALLET__RPC_USER", "user")
        self._password = rpc_password or os.environ.get(
            "ELIANA_WALLET__RPC_PASSWORD", "")
        # 安全預設 testnet；要用 mainnet 必須明確設定
        self._network = (network or os.environ.get(
            "ELIANA_WALLET__NETWORK", "testnet")).lower()
        self._rpc_id = 0

    async def _call(self, method: str, params: Optional[list] = None) -> Any:
        import httpx
        self._rpc_id += 1
        payload = {"id": self._rpc_id, "method": method, "params": params or []}
        async with httpx.AsyncClient(timeout=httpx.Timeout(40.0, connect=10.0)) as c:
            r = await c.post(self._url, json=payload,
                             auth=(self._user, self._password))
            r.raise_for_status()
            data = r.json()
        if data.get("error"):
            raise ElectrumRpcError(f"{method}: {data['error']}")
        return data.get("result")

    async def connect(self, server: str = "") -> bool:
        """確認 daemon 連線，並鎖定 network（期望與 daemon 實際一致）。"""
        info = await self._call("getinfo")
        actual = str(info.get("network", "")).lower()
        if actual != self._network:
            raise ElectrumRpcError(
                f"network mismatch: expected {self._network!r} but daemon is "
                f"{actual!r}; refusing to proceed (mainnet safety)")
        return bool(info.get("connected", False))

    async def create_new_address(self) -> str:
        """產生 BIP-84 接收地址（testnet 應為 tb1q 開頭）。"""
        return str(await self._call("getunusedaddress"))

    async def get_balance(self) -> dict:
        """回傳餘額（sat 整數）。Electrum 回 BTC 字串，轉為 sat 並正規化欄位。"""
        raw = await self._call("getbalance") or {}

        def _to_sat(v) -> int:
            if v is None:
                return 0
            # Electrum 回 BTC 字串（如 "0" / "0.0001"）
            from decimal import Decimal
            return int((Decimal(str(v)) * Decimal(10) ** 8).to_integral_value())

        return {
            "confirmed": _to_sat(raw.get("confirmed", 0)),
            "unconfirmed": _to_sat(raw.get("unconfirmed", 0)),
        }

    async def list_transactions(self) -> list[dict]:
        """回傳 onchain 交易列表。"""
        hist = await self._call("onchain_history") or {}
        return list(hist.get("transactions", []))


# --------------------------------------------------------------------------- #
# bech32 驗證（BIP-173）
# --------------------------------------------------------------------------- #
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: list[int]) -> int:
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp: str, data: list[int]) -> bool:
    return _bech32_polymod(_bech32_hrp_expand(hrp) + data) == 1


def is_valid_bech32_address(address: str) -> bool:
    """驗證 bech32 地址編碼是否有效（BIP-173）。

    僅驗證編碼與 checksum 正確性，不驗證 witness program 語意。
    """
    if not address:
        return False
    addr = address.lower()
    # 不允許大小寫混用
    if address != addr and address != address.upper():
        return False
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        return False
    hrp = addr[:pos]
    data_part = addr[pos + 1:]
    if any(c not in _BECH32_CHARSET for c in data_part):
        return False
    data = [_BECH32_CHARSET.index(c) for c in data_part]
    return bech32_verify_checksum(hrp, data)
