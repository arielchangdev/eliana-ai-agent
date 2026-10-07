"""EvolutionManager：人格演化流程、閾值與版本控管。

- apply_suggestions：累計 < 15% 自動套用（applied）；>= 15% 標 pending + 通知。
  套用前過濾冷卻期內的同方向建議。
- reject_direction：插入冷卻記錄（30 次對話）。
- accept_pending：將 pending 建議標記 applied 並套用。
- decrement_cooldowns：每次對話後遞減冷卻計數。
- get_version_history / rollback_to_version：版本歷史（<=100）與回溯。
- check_threshold / get_evolution_timeline。
"""
from __future__ import annotations

import json
from typing import Callable, Optional
from uuid import uuid4

from .db import EvolutionDB
from .engine import PersonalityEngine
from .exceptions import VersionNotFoundError
from .models import (
    ApplyResult,
    EvolutionSuggestion,
    ParameterChange,
    PersonalityProfile,
    ThresholdStatus,
)

THRESHOLD_PERCENT = 15.0


def _direction(change: ParameterChange) -> str:
    """依 change_percent 正負決定方向。"""
    return "increase" if change.change_percent >= 0 else "decrease"


class EvolutionManager:
    def __init__(
        self,
        db: EvolutionDB,
        engine: PersonalityEngine,
        notify_callback: Optional[Callable[[str], None]] = None,
    ):
        self.db = db
        self.engine = engine
        self._notify_callback = notify_callback

    # ----- 套用建議 ------------------------------------------------------- #
    async def apply_suggestions(
        self, suggestions: list[EvolutionSuggestion]
    ) -> ApplyResult:
        """套用建議。逐一處理每個 ParameterChange：

        - 若該 (parameter_path, direction) 在冷卻期內 → 過濾（不套用）
        - 若套用後累計 < 15% → applied，更新累計，實際套用至人格
        - 若套用後累計 >= 15% → pending，標記並通知（不套用）
        """
        result = ApplyResult()
        cooldowns = await self._active_cooldown_set()
        applied_changes: list[ParameterChange] = []

        for suggestion in suggestions:
            suggestion_status = "applied"
            suggestion_has_change = False
            for change in suggestion.changes:
                key = (change.parameter_path, _direction(change))
                if key in cooldowns:
                    # 冷卻期內同方向 → 過濾
                    result.filtered.append(suggestion.id)
                    continue

                suggestion_has_change = True
                current_cumulative = await self.db.get_cumulative(
                    change.parameter_path
                )
                new_cumulative = current_cumulative + abs(change.change_percent)

                if new_cumulative >= THRESHOLD_PERCENT:
                    # 達閾值 → pending + 通知，不套用
                    await self._log(suggestion.id, change, "pending")
                    suggestion_status = "pending"
                    self._notify(
                        f"參數 {change.parameter_path} 累計變化 "
                        f"{new_cumulative:.1f}% 已達閾值，暫停自動演化待確認"
                    )
                else:
                    # 自動套用
                    await self.db.update_cumulative(
                        change.parameter_path, new_cumulative
                    )
                    await self._log(suggestion.id, change, "applied")
                    applied_changes.append(change)

            if not suggestion_has_change:
                continue
            if suggestion_status == "pending":
                result.pending.append(suggestion.id)
            else:
                result.applied.append(suggestion.id)

        # 實際套用已通過的變更至人格
        if applied_changes:
            await self.engine.apply_evolution(applied_changes)

        return result

    async def _active_cooldown_set(self) -> set[tuple[str, str]]:
        cooldowns = await self.db.get_active_cooldowns()
        return {(c["parameter_path"], c["direction"]) for c in cooldowns}

    async def _log(
        self, suggestion_id: str, change: ParameterChange, status: str
    ) -> None:
        await self.db.insert_evolution_log(
            log_id=str(uuid4()),
            suggestion_id=suggestion_id,
            parameter_path=change.parameter_path,
            old_value=str(change.current_value),
            new_value=str(change.suggested_value),
            change_percent=change.change_percent,
            status=status,
        )

    # ----- 拒絕冷卻與接受 ------------------------------------------------- #
    async def reject_direction(self, parameter_path: str, direction: str) -> None:
        """拒絕特定方向演化，30 次對話冷卻。"""
        if direction not in ("increase", "decrease"):
            raise ValueError(f"無效方向: {direction}")
        await self.db.insert_cooldown(
            cooldown_id=str(uuid4()),
            parameter_path=parameter_path,
            direction=direction,
            remaining=30,
        )

    async def accept_pending(
        self, suggestion_ids: list[str]
    ) -> PersonalityProfile:
        """使用者確認接受待定演化，套用並標記 applied。"""
        logs = await self.db.get_evolution_logs(status="pending")
        changes: list[ParameterChange] = []
        for log in logs:
            if log["suggestion_id"] not in suggestion_ids:
                continue
            changes.append(ParameterChange(
                parameter_path=log["parameter_path"],
                current_value=_coerce(log["old_value"]),
                suggested_value=_coerce(log["new_value"]),
                change_percent=log["change_percent"],
                reason="使用者確認接受",
            ))
            # 更新累計並標記 applied
            cur = await self.db.get_cumulative(log["parameter_path"])
            await self.db.update_cumulative(
                log["parameter_path"], cur + abs(log["change_percent"])
            )
        for sid in suggestion_ids:
            await self.db.update_log_status(sid, "applied")
        if changes:
            return await self.engine.apply_evolution(changes)
        return self.engine.get_active_profile()

    async def decrement_cooldowns(self) -> None:
        """每次對話結束後遞減冷卻計數。"""
        await self.db.decrement_cooldowns()

    # ----- 版本歷史與回溯 ------------------------------------------------- #
    async def get_version_history(self, limit: int = 100):
        """取得版本歷史（最多 100 筆，最新在前）。"""
        limit = min(limit, 100)
        return await self.db.get_versions(limit=limit)

    async def rollback_to_version(self, version_id: str) -> PersonalityProfile:
        """回溯至指定版本並立即生效。"""
        version = await self.db.get_version(version_id)
        if version is None:
            raise VersionNotFoundError(version_id)
        snapshot = json.loads(version["profile_snapshot"])
        profile = PersonalityProfile.model_validate(snapshot)
        self.engine.set_active_profile(profile)
        await self.engine.save_profile()
        # 記錄一筆 rollback 版本快照
        await self.engine.snapshot_version(
            source="rollback",
            summary=f"回溯至版本 {version['version_number']}",
        )
        return profile

    async def get_evolution_timeline(self) -> dict[str, list[dict]]:
        """聚合各參數隨時間的變化趨勢資料。"""
        logs = await self.db.get_evolution_logs(status="applied")
        timeline: dict[str, list[dict]] = {}
        for log in logs:
            path = log["parameter_path"]
            timeline.setdefault(path, []).append({
                "change_percent": log["change_percent"],
                "new_value": log["new_value"],
                "created_at": log["created_at"],
            })
        return timeline

    async def check_threshold(self, parameter_path: str) -> ThresholdStatus:
        cumulative = await self.db.get_cumulative(parameter_path)
        return ThresholdStatus(
            parameter_path=parameter_path,
            cumulative_percent=cumulative,
            threshold=THRESHOLD_PERCENT,
            exceeded=cumulative >= THRESHOLD_PERCENT,
        )

    # ----- helper --------------------------------------------------------- #
    def _notify(self, message: str) -> None:
        if self._notify_callback is not None:
            try:
                self._notify_callback(message)
            except Exception:  # noqa: BLE001
                pass


def _coerce(value: str):
    """嘗試將字串轉為 float，失敗則保留字串。"""
    try:
        return float(value)
    except (ValueError, TypeError):
        return value
