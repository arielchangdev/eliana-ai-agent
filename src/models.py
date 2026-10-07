"""核心資料模型：Enum 與 dataclass 定義。

所有欄位型別與 design.md 保持一致。embedding 向量固定為 384 維
（all-MiniLM-L6-v2），category_tags 為 CategoryTag 列表。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

# 嵌入向量維度（all-MiniLM-L6-v2）
EMBEDDING_DIM = 384


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class FileFormat(Enum):
    TXT = "txt"
    MARKDOWN = "markdown"
    PDF = "pdf"
    HTML = "html"
    PYTHON = "python"
    SHELL = "shell"
    YAML = "yaml"


class SourceType(Enum):
    NVD = "nvd"
    GITHUB_ADVISORY = "github_advisory"
    EXPLOIT_DB = "exploit_db"
    RSS = "rss"
    USER_UPLOAD = "user_upload"


class CategoryTag(Enum):
    VULNERABILITY_TYPE = "vulnerability_type"
    TOOL_USAGE = "tool_usage"
    ATTACK_TECHNIQUE = "attack_technique"
    DEFENSE_BYPASS = "defense_bypass"


class StrategyStatus(Enum):
    ACTIVE = "active"
    HIGH_EFFICIENCY = "high_efficiency"
    NEEDS_OPTIMIZATION = "needs_optimization"
    DEPRECATED = "deprecated"


# --------------------------------------------------------------------------- #
# Core domain models
# --------------------------------------------------------------------------- #
@dataclass
class KnowledgeFragment:
    id: str
    text: str
    embedding: list[float]
    source_type: SourceType
    source_url: Optional[str]
    category_tags: list[CategoryTag]
    created_at: datetime
    last_referenced_at: Optional[datetime] = None
    reference_count: int = 0
    token_count: int = 0


@dataclass
class DetectionStrategy:
    id: str
    name: str
    description: str
    vulnerability_types: list[str]
    tools: list[str]
    weight: float = 1.0
    status: StrategyStatus = StrategyStatus.ACTIVE
    success_count: int = 0
    failure_count: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class TaskResult:
    task_id: str
    strategy_id: str
    target_type: str
    outcome: str  # "success" | "failure" | "rejected"
    details: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class RetryConfig:
    initial_wait: float = 60.0
    max_wait: float = 1800.0
    max_retries: int = 3
    backoff_factor: float = 2.0


@dataclass
class CrawlSource:
    url: str
    source_type: SourceType
    schedule_cron: str = "0 2 * * *"
    robots_respected: bool = True
    retry_config: RetryConfig = field(default_factory=RetryConfig)


@dataclass
class TextChunk:
    text: str
    token_count: int
    start_offset: int
    end_offset: int


@dataclass
class ProcessResult:
    fragments_created: int
    total_tokens: int
    category_distribution: dict[str, int]
    errors: list[str] = field(default_factory=list)


@dataclass
class SearchFilters:
    category_tags: Optional[list[CategoryTag]] = None
    source_types: Optional[list[SourceType]] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None


@dataclass
class WeightAdjustment:
    factor: float
    new_status: str
    reason: str = ""


@dataclass
class SearchResult:
    fragment: KnowledgeFragment
    score: float


@dataclass
class UpsertResult:
    inserted: int
    merged: int
    errors: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# 補充模型（design 中介面引用但未列於 Data Models 章節）
# --------------------------------------------------------------------------- #
@dataclass
class RawContent:
    """爬蟲取回的原始內容。"""
    source_type: SourceType
    source_url: str
    text: str
    title: Optional[str] = None
    fetched_at: datetime = field(default_factory=datetime.now)


@dataclass
class SourceMeta:
    """供 process_text 使用的來源元資料。"""
    source_type: SourceType
    source_url: Optional[str] = None
    category_tags: list[CategoryTag] = field(default_factory=list)


@dataclass
class UploadMeta:
    """使用者上傳檔案的元資料。"""
    filename: str
    source_type: SourceType = SourceType.USER_UPLOAD
    category_tags: list[CategoryTag] = field(default_factory=list)


@dataclass
class DedupResult:
    is_duplicate: bool
    matched_fragment_id: Optional[str] = None
    similarity: float = 0.0


@dataclass
class ArchiveResult:
    archived: int
    remaining: int
    errors: list[str] = field(default_factory=list)


@dataclass
class VectorStoreStats:
    total_fragments: int
    category_distribution: dict[str, int]
    source_distribution: dict[str, int]


@dataclass
class SourceHealth:
    source_type: str
    source_url: str
    success_count: int
    failure_count: int
    rate_limited_count: int
    last_crawled_at: Optional[datetime] = None

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        return self.success_count / total if total else 0.0


@dataclass
class CrawlResult:
    sources_attempted: int
    sources_succeeded: int
    sources_skipped: int
    fragments_created: int
    errors: list[str] = field(default_factory=list)


@dataclass
class StrategyAdjustment:
    strategy_id: str
    previous_weight: float
    new_weight: float
    new_status: str
    reason: str
    success_rate: float


@dataclass
class StrategyTrend:
    strategy_id: str
    name: str
    success_rate: float
    current_weight: float
    weight_changes: int


# --------------------------------------------------------------------------- #
# 報告模型
# --------------------------------------------------------------------------- #
@dataclass
class KnowledgeGrowth:
    new_fragments: int
    source_distribution: dict[str, int]
    category_distribution: dict[str, int]
    total_capacity: int


@dataclass
class StrategyPerformance:
    trends: list[StrategyTrend]
    weight_adjustments: list[StrategyAdjustment]
    new_strategies: list[str]
    deprecated_strategies: list[str]


@dataclass
class CrawlHealthSummary:
    per_source: dict[str, SourceHealth]
    total_success: int
    total_failed: int
    total_rate_limited: int


@dataclass
class ReportResult:
    year: int
    month: int
    report_path: str
    markdown: str
