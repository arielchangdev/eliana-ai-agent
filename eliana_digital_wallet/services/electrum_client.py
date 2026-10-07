"""Electrum daemon 介面（Protocol）與 bech32 工具。

以 Protocol 定義注入式介面，讓 WalletManager 不直接相依實際 Electrum
daemon，便於測試以 mock 替代。真實實作於整合階段接 Electrum JSON-RPC。
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


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
