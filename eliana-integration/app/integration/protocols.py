"""子系統標準介面定義。

每個子系統（Core_Infra、Bounty_Hunter、Digital_Wallet、Learning_Engine、
Personality、Dashboard）皆透過 Adapter 實作 SubsystemProtocol，
使 Integration_App 得以統一管理其生命週期與健康檢查。
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import ModuleHealth


@runtime_checkable
class SubsystemProtocol(Protocol):
    """子系統標準生命週期介面。"""

    name: str

    async def initialize(self) -> None:
        """初始化子系統資源（連線、載入設定等）。"""
        ...

    async def start(self) -> None:
        """啟動子系統。"""
        ...

    async def stop(self) -> None:
        """停止子系統並釋放資源。"""
        ...

    async def health_check(self) -> ModuleHealth:
        """回報子系統目前的健康狀態。"""
        ...
