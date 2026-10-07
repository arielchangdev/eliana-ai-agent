"""Config_Manager — 統一配置管理器。

載入統一 YAML 設定檔（eliana.yaml），以 jsonschema 驗證結構；支援
ELIANA_ 前綴環境變數覆寫（雙底線 __ 表示層級分隔）；偵測執行期變更並
通知受影響子系統重載；重載失敗時保留舊配置並記錄 error。
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any, Awaitable, Callable

import structlog
import yaml
from jsonschema import Draft7Validator

from .exceptions import ConfigValidationError

logger = structlog.get_logger(__name__)

ENV_PREFIX = "ELIANA_"
LEVEL_SEP = "__"

ReloadCallback = Callable[[dict], Awaitable[None]] | Callable[[dict], None]


def _coerce(value: str) -> Any:
    """將環境變數字串轉為合理的 Python 型別（int/float/bool/None/str）。"""
    low = value.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "none"):
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def apply_env_overrides(config: dict, environ: dict[str, str] | None = None) -> dict:
    """套用 ELIANA_ 前綴環境變數覆寫。

    例：ELIANA_DATABASE__PORT=5433 → config['database']['port'] = 5433
    層級鍵一律小寫化。回傳新的（深拷貝後修改的）dict。
    """
    env = environ if environ is not None else dict(os.environ)
    result = copy.deepcopy(config)
    for key, raw in env.items():
        if not key.startswith(ENV_PREFIX):
            continue
        path = key[len(ENV_PREFIX):].split(LEVEL_SEP)
        path = [p.lower() for p in path if p != ""]
        if not path:
            continue
        node = result
        for part in path[:-1]:
            nxt = node.get(part)
            if not isinstance(nxt, dict):
                nxt = {}
                node[part] = nxt
            node = nxt
        node[path[-1]] = _coerce(raw)
    return result


class ConfigManager:
    """統一配置管理器。"""

    def __init__(
        self,
        config_path: str | Path | None = None,
        schema: dict | None = None,
        *,
        environ: dict[str, str] | None = None,
    ) -> None:
        self._path = Path(config_path) if config_path else None
        self._schema = schema
        self._environ = environ
        self._config: dict = {}
        self._raw: dict = {}
        self._reload_callbacks: list[ReloadCallback] = []
        self._last_mtime: float | None = None

    # ------------------------------------------------------------------ #
    def on_reload(self, cb: ReloadCallback) -> None:
        self._reload_callbacks.append(cb)

    def validate_schema(self, config: dict) -> list[str]:
        """回傳驗證錯誤訊息清單（空清單表示通過）。"""
        if self._schema is None:
            return []
        validator = Draft7Validator(self._schema)
        errors = []
        for err in sorted(validator.iter_errors(config), key=lambda e: list(e.path)):
            loc = "/".join(str(p) for p in err.path) or "<root>"
            errors.append(f"{loc}: {err.message}")
        return errors

    def load(self, data: dict | None = None) -> dict:
        """載入配置。data 提供時直接用（測試用），否則讀 YAML 檔。

        流程：讀取 → 套用 env 覆寫 → schema 驗證 → 存入。
        驗證失敗拋 ConfigValidationError（保留既有 self._config）。
        """
        if data is not None:
            raw = copy.deepcopy(data)
        elif self._path is not None:
            text = self._path.read_text(encoding="utf-8")
            raw = yaml.safe_load(text) or {}
            self._last_mtime = self._path.stat().st_mtime
        else:
            raw = {}

        merged = apply_env_overrides(raw, self._environ)
        errors = self.validate_schema(merged)
        if errors:
            raise ConfigValidationError(
                "config schema validation failed", errors=errors,
            )
        self._raw = raw
        self._config = merged
        return self._config

    def get(self, key: str, default: Any = None) -> Any:
        """以點號路徑取值，如 get('database.port')。"""
        node: Any = self._config
        for part in key.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return node

    @property
    def config(self) -> dict:
        return self._config

    async def reload(self, data: dict | None = None) -> bool:
        """重新載入配置。成功回傳 True 並通知 callbacks；失敗保留舊配置回傳 False。"""
        old = copy.deepcopy(self._config)
        try:
            self.load(data)
        except ConfigValidationError as exc:
            self._config = old
            logger.error("config_reload_failed", errors=exc.errors)
            return False
        except Exception as exc:  # noqa: BLE001
            self._config = old
            logger.error("config_reload_failed", error=str(exc))
            return False

        await self._notify_reload()
        return True

    def detect_change(self) -> bool:
        """偵測設定檔 mtime 是否變更。"""
        if self._path is None or not self._path.exists():
            return False
        mtime = self._path.stat().st_mtime
        return self._last_mtime is not None and mtime != self._last_mtime

    async def _notify_reload(self) -> None:
        import inspect

        for cb in self._reload_callbacks:
            result = cb(self._config)
            if inspect.isawaitable(result):
                await result
