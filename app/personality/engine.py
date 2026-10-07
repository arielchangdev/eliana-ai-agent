"""PersonalityEngine：人格引擎核心。

管理人格生命週期：載入/儲存（JSON+YAML 雙格式）、驗證/衝突檢測、
匯出/匯入、演化套用（含自動備份 + 版本快照）。
檔案 I/O 以 asyncio.to_thread 包裝，避免對 aiofiles 的硬相依。
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

import yaml

from .db import EvolutionDB
from .exceptions import ValidationError
from .models import ParameterChange, PersonalityProfile, ValidationResult

_ACTIVE_JSON = "active_profile.json"
_ACTIVE_YAML = "active_profile.yaml"


class PersonalityEngine:
    def __init__(self, profile_dir: str | Path, db: EvolutionDB):
        self.profile_dir = Path(profile_dir)
        self.db = db
        self._active: Optional[PersonalityProfile] = None

    # ----- 載入與儲存 ----------------------------------------------------- #
    async def load_profile(
        self, path: Optional[str | Path] = None
    ) -> PersonalityProfile:
        """從 JSON/YAML 檔載入人格設定並快取。"""
        target = Path(path) if path else self.profile_dir / _ACTIVE_JSON
        raw = await asyncio.to_thread(target.read_text, "utf-8")
        profile = self._parse(raw, target.suffix)
        self._active = profile
        return profile

    async def save_profile(
        self, fmt: Literal["json", "yaml"] = "json"
    ) -> Path:
        """同步寫入 JSON 與 YAML 雙格式，回傳主要格式路徑。"""
        if self._active is None:
            raise ValueError("無生效人格可儲存")
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        json_path = self.profile_dir / _ACTIVE_JSON
        yaml_path = self.profile_dir / _ACTIVE_YAML
        await asyncio.to_thread(json_path.write_text, self._to_json(self._active), "utf-8")
        await asyncio.to_thread(yaml_path.write_text, self._to_yaml(self._active), "utf-8")
        return json_path if fmt == "json" else yaml_path

    def get_active_profile(self) -> PersonalityProfile:
        if self._active is None:
            raise ValueError("尚無生效人格，請先載入或設定")
        return self._active

    def set_active_profile(self, profile: PersonalityProfile) -> None:
        self._active = profile

    # ----- 驗證與衝突 ----------------------------------------------------- #
    async def validate_profile(
        self, profile: PersonalityProfile
    ) -> ValidationResult:
        """驗證必填完整性與衝突檢測。

        - 缺必填 / 型別錯誤：valid=False + errors（由 Pydantic 建構時已擋下）
        - 衝突模式：valid=True + warnings（允許但需確認）
        """
        errors: list[str] = []
        # tone_styles 必須 1-6 個（Pydantic 已驗，但重複檢查以產生友善訊息）
        if not profile.tone_styles:
            errors.append("tone_styles 不可為空")
        if len(profile.tone_styles) > 6:
            errors.append("tone_styles 不可超過 6 個")

        warnings = profile.detect_conflicts()
        return ValidationResult(
            valid=len(errors) == 0, errors=errors, warnings=warnings
        )

    # ----- 匯出與匯入 ----------------------------------------------------- #
    async def export_profile(
        self, dest: str | Path, fmt: Literal["json", "yaml"] = "json"
    ) -> Path:
        """匯出含元資料的完整設定檔。"""
        if self._active is None:
            raise ValueError("無生效人格可匯出")
        dest_path = Path(dest)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        content = (
            self._to_json(self._active) if fmt == "json"
            else self._to_yaml(self._active)
        )
        await asyncio.to_thread(dest_path.write_text, content, "utf-8")
        return dest_path

    async def import_profile(self, src: str | Path) -> PersonalityProfile:
        """匯入並驗證外部設定檔，失敗時列出具體錯誤。"""
        src_path = Path(src)
        if not src_path.exists():
            raise ValidationError([f"檔案不存在: {src_path}"])
        raw = await asyncio.to_thread(src_path.read_text, "utf-8")
        try:
            profile = self._parse(raw, src_path.suffix)
        except Exception as exc:  # noqa: BLE001 - 解析/驗證錯誤統一包裝
            raise ValidationError([f"設定檔無效: {exc}"])
        return profile

    # ----- 演化套用 ------------------------------------------------------- #
    async def apply_evolution(
        self, changes: list[ParameterChange]
    ) -> PersonalityProfile:
        """套用 ParameterChange 列表：先備份 → 更新欄位 → 版本快照。"""
        if self._active is None:
            raise ValueError("無生效人格可演化")

        # 1. 自動備份舊版本
        await self._backup(self._active)

        # 2. 套用變更（在副本上操作）
        data = self._active.model_dump()
        for change in changes:
            _apply_path(data, change.parameter_path, change.suggested_value)
        data["version"] = self._active.version + 1
        data["updated_at"] = datetime.now(timezone.utc)
        new_profile = PersonalityProfile.model_validate(data)
        self._active = new_profile

        # 3. 版本快照
        version_number = await self.db.get_max_version_number() + 1
        import uuid
        summary = "; ".join(
            f"{c.parameter_path}:{c.change_percent:+.1f}%" for c in changes
        ) or "無變更"
        await self.db.insert_version(
            version_id=str(uuid.uuid4()),
            version_number=version_number,
            profile_snapshot=self._to_json(new_profile),
            change_summary=summary,
            source="evolution",
        )
        # 同步存檔
        await self.save_profile()
        return new_profile

    async def snapshot_version(
        self, source: str = "manual", summary: str = ""
    ) -> int:
        """為當前生效人格建立版本快照，回傳 version_number。"""
        if self._active is None:
            raise ValueError("無生效人格")
        import uuid
        version_number = await self.db.get_max_version_number() + 1
        await self.db.insert_version(
            version_id=str(uuid.uuid4()),
            version_number=version_number,
            profile_snapshot=self._to_json(self._active),
            change_summary=summary or "手動快照",
            source=source,
        )
        return version_number

    # ----- helper --------------------------------------------------------- #
    async def _backup(self, profile: PersonalityProfile) -> Path:
        backup_dir = self.profile_dir / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        backup_path = backup_dir / f"profile_{ts}.json"
        await asyncio.to_thread(
            backup_path.write_text, self._to_json(profile), "utf-8"
        )
        return backup_path

    @staticmethod
    def _parse(raw: str, suffix: str) -> PersonalityProfile:
        if suffix.lower() in (".yaml", ".yml"):
            data = yaml.safe_load(raw)
        else:
            data = json.loads(raw)
        return PersonalityProfile.model_validate(data)

    @staticmethod
    def _to_json(profile: PersonalityProfile) -> str:
        return profile.model_dump_json(indent=2)

    @staticmethod
    def _to_yaml(profile: PersonalityProfile) -> str:
        # 經 JSON 正規化（datetime/enum -> 原生型別）後轉 YAML
        data = json.loads(profile.model_dump_json())
        return yaml.safe_dump(data, allow_unicode=True, sort_keys=False)


def _apply_path(data: dict, path: str, value) -> None:
    """依 dotted path 設定巢狀欄位值。"""
    parts = path.split(".")
    node = data
    for p in parts[:-1]:
        node = node.setdefault(p, {})
    node[parts[-1]] = value
