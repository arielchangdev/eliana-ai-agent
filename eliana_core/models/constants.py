"""核心常數定義."""

from .task import TaskCategory, HostTarget
from .metrics import AlertLevel


# 任務分派規則映射
CATEGORY_TO_HOST: dict[TaskCategory, HostTarget] = {
    TaskCategory.SECURITY_TOOL: HostTarget.WEAPON,
    TaskCategory.RECONNAISSANCE: HostTarget.WEAPON,
    TaskCategory.EXPLOITATION: HostTarget.WEAPON,
    TaskCategory.COMPUTATION: HostTarget.CORE,
    TaskCategory.LLM_INFERENCE: HostTarget.CORE,
    TaskCategory.ANALYSIS: HostTarget.CORE,
}


# 告警閾值設定
ALERT_THRESHOLDS = {
    "cpu_critical": {"threshold": 90.0, "duration_seconds": 60, "level": AlertLevel.CRITICAL},
    "memory_warning": {"threshold": 85.0, "duration_seconds": 0, "level": AlertLevel.WARNING},
    "disk_warning": {"threshold": 80.0, "duration_seconds": 0, "level": AlertLevel.WARNING},
}


# 量化等級降級路徑（從最高品質到最低品質）
QUANTIZATION_LEVELS = ["Q8_0", "Q6_K", "Q5_K_M", "Q4_K_M", "Q4_0", "Q3_K_S", "Q2_K"]

# 各量化等級相對於完整模型大小的記憶體比率
QUANTIZATION_RATIOS: dict[str, float] = {
    "Q8_0": 1.0,
    "Q6_K": 0.75,
    "Q5_K_M": 0.625,
    "Q4_K_M": 0.5,
    "Q4_0": 0.5,
    "Q3_K_S": 0.375,
    "Q2_K": 0.25,
}