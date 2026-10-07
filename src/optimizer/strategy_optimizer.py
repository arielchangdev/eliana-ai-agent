"""Strategy_Optimizer：策略自適應最佳化。

根據 bounty-hunter 回饋的任務結果，動態調整偵測策略權重：
- 最近 5 次成功率 > 60% → 權重 × 1.20，狀態 "high_efficiency"
- 最近 5 次成功率 < 20% → 權重 × 0.70，狀態 "needs_optimization"
每次調整寫入 strategy_history。全局平均成功率 < 10% 觸發告警。
"""
from __future__ import annotations

import uuid
from typing import Optional

from ..db import WEIGHT_MAX, WEIGHT_MIN, SQLiteDB, clamp_weight
from ..models import (
    DetectionStrategy,
    StrategyAdjustment,
    StrategyStatus,
    StrategyTrend,
    TaskResult,
    WeightAdjustment,
)

# 演算法常數（與 config.yaml 一致）
EVAL_WINDOW = 5
HIGH_EFFICIENCY_THRESHOLD = 0.60
HIGH_EFFICIENCY_FACTOR = 1.20
NEEDS_OPT_THRESHOLD = 0.20
NEEDS_OPT_FACTOR = 0.70
GLOBAL_ALERT_THRESHOLD = 0.10


def compute_adjustment(last_outcomes: list[str]) -> Optional[WeightAdjustment]:
    """依最近結果計算權重調整。

    成功率 = success 次數 / 樣本數（需恰好 EVAL_WINDOW 個樣本才評估）。
    > 60% → factor 1.20 / high_efficiency
    < 20% → factor 0.70 / needs_optimization
    其餘 → None（不調整）
    """
    if len(last_outcomes) < EVAL_WINDOW:
        return None
    window = last_outcomes[:EVAL_WINDOW]
    success_rate = sum(1 for o in window if o == "success") / EVAL_WINDOW
    if success_rate > HIGH_EFFICIENCY_THRESHOLD:
        return WeightAdjustment(
            factor=HIGH_EFFICIENCY_FACTOR,
            new_status="high_efficiency",
            reason=f"連續{EVAL_WINDOW}次成功率{success_rate:.0%}",
        )
    if success_rate < NEEDS_OPT_THRESHOLD:
        return WeightAdjustment(
            factor=NEEDS_OPT_FACTOR,
            new_status="needs_optimization",
            reason=f"連續{EVAL_WINDOW}次成功率{success_rate:.0%}",
        )
    return None


class StrategyOptimizer:
    def __init__(self, db: SQLiteDB, vector_store=None):
        self.db = db
        self.vector_store = vector_store

    # ----- 記錄結果 ------------------------------------------------------- #
    async def record_result(self, result: TaskResult) -> None:
        """記錄任務結果至 SQLite。"""
        await self.db.insert_task_result(result)

    # ----- 評估與調整 ----------------------------------------------------- #
    async def evaluate_strategies(self) -> list[StrategyAdjustment]:
        """評估所有策略，對符合條件者執行調整並回傳清單。"""
        strategies = await self.db.get_all_strategies()
        adjustments: list[StrategyAdjustment] = []
        for strategy in strategies:
            adj = await self._evaluate_one(strategy)
            if adj is not None:
                adjustments.append(adj)
        return adjustments

    async def _evaluate_one(
        self, strategy: DetectionStrategy
    ) -> Optional[StrategyAdjustment]:
        recent = await self.db.get_recent_results_by_strategy(
            strategy.id, limit=EVAL_WINDOW
        )
        outcomes = [r["outcome"] for r in recent]
        weight_adj = compute_adjustment(outcomes)
        if weight_adj is None:
            return None

        success_rate = (
            sum(1 for o in outcomes[:EVAL_WINDOW] if o == "success") / EVAL_WINDOW
        )
        adjustment = StrategyAdjustment(
            strategy_id=strategy.id,
            previous_weight=strategy.weight,
            new_weight=clamp_weight(strategy.weight * weight_adj.factor),
            new_status=weight_adj.new_status,
            reason=weight_adj.reason,
            success_rate=success_rate,
        )
        await self.adjust_weight(strategy.id, weight_adj, strategy=strategy,
                                 success_rate=success_rate)
        return adjustment

    async def adjust_weight(
        self,
        strategy_id: str,
        adj: WeightAdjustment,
        strategy: Optional[DetectionStrategy] = None,
        success_rate: Optional[float] = None,
    ) -> None:
        """執行權重調整並寫入 strategy_history。"""
        if strategy is None:
            strategy = await self.db.get_strategy(strategy_id)
        if strategy is None:
            raise ValueError(f"策略不存在: {strategy_id}")

        previous_weight = strategy.weight
        new_weight = clamp_weight(previous_weight * adj.factor)

        await self.db.update_strategy_weight(
            strategy_id, new_weight, adj.new_status
        )
        await self.db.insert_strategy_history(
            strategy_id=strategy_id,
            previous_weight=previous_weight,
            new_weight=new_weight,
            trigger_reason=adj.reason,
            success_rate=success_rate,
        )

    # ----- 告警 ----------------------------------------------------------- #
    async def check_alert_condition(self) -> bool:
        """所有策略的平均成功率 < 10% → True。無策略時回傳 False。"""
        strategies = await self.db.get_all_strategies()
        if not strategies:
            return False
        rates: list[float] = []
        for strategy in strategies:
            recent = await self.db.get_recent_results_by_strategy(
                strategy.id, limit=EVAL_WINDOW
            )
            if not recent:
                rates.append(0.0)
                continue
            rate = sum(1 for r in recent if r["outcome"] == "success") / len(recent)
            rates.append(rate)
        avg = sum(rates) / len(rates)
        return avg < GLOBAL_ALERT_THRESHOLD

    # ----- 趨勢 ----------------------------------------------------------- #
    async def get_trends(self, months: int = 1) -> list[StrategyTrend]:
        """回傳各策略效能趨勢。"""
        strategies = await self.db.get_all_strategies()
        trends: list[StrategyTrend] = []
        for strategy in strategies:
            recent = await self.db.get_recent_results_by_strategy(
                strategy.id, limit=EVAL_WINDOW
            )
            rate = (
                sum(1 for r in recent if r["outcome"] == "success") / len(recent)
                if recent
                else 0.0
            )
            history = await self.db.get_strategy_history(strategy.id)
            trends.append(
                StrategyTrend(
                    strategy_id=strategy.id,
                    name=strategy.name,
                    success_rate=rate,
                    current_weight=strategy.weight,
                    weight_changes=len(history),
                )
            )
        return trends

    # ----- 新策略建議（Task 8.4） ----------------------------------------- #
    async def suggest_strategies(
        self, knowledge_hints: list[dict]
    ) -> list[DetectionStrategy]:
        """根據最新知識提示產生新策略建議（待使用者確認）。

        knowledge_hints 為字典列表，每筆含：
        - name / description
        - vulnerability_types: list[str]
        - tools: list[str]
        回傳的策略標記為 DEPRECATED（代表待確認，未啟用），
        經使用者確認後可改為 ACTIVE 並寫入策略庫。
        """
        suggestions: list[DetectionStrategy] = []
        for hint in knowledge_hints:
            vuln_types = hint.get("vulnerability_types", [])
            tools = hint.get("tools", [])
            if not vuln_types and not tools:
                continue
            suggestions.append(
                DetectionStrategy(
                    id=f"suggested-{uuid.uuid4().hex[:8]}",
                    name=hint.get("name", "建議策略"),
                    description=hint.get("description", ""),
                    vulnerability_types=vuln_types,
                    tools=tools,
                    weight=1.0,
                    status=StrategyStatus.DEPRECATED,  # 待確認
                )
            )
        return suggestions

    async def confirm_strategy(self, strategy: DetectionStrategy) -> None:
        """使用者確認後將建議策略加入策略庫（狀態設為 ACTIVE）。"""
        strategy.status = StrategyStatus.ACTIVE
        await self.db.upsert_strategy(strategy)
