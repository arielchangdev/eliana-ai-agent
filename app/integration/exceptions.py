"""整合模組例外階層。"""
from __future__ import annotations


class ElianaIntegrationError(Exception):
    """整合模組所有例外的基底類別。"""


class EventBusError(ElianaIntegrationError):
    """Event_Bus 相關錯誤（分派失敗、佇列異常等）。"""


class PipelineError(ElianaIntegrationError):
    """Pipeline_Orchestrator 執行錯誤。"""

    def __init__(self, message: str, *, stage: str | None = None,
                 pipeline_id: str | None = None) -> None:
        super().__init__(message)
        self.stage = stage
        self.pipeline_id = pipeline_id


class ConfigValidationError(ElianaIntegrationError):
    """配置驗證失敗，攜帶具體錯誤清單。"""

    def __init__(self, message: str, *, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.errors: list[str] = errors or []


class StartupValidationError(ElianaIntegrationError):
    """啟動驗證失敗，攜帶失敗元件清單。"""

    def __init__(self, message: str, *, failed_components: list[str] | None = None) -> None:
        super().__init__(message)
        self.failed_components: list[str] = failed_components or []
