"""Bounty 模組資料模型。

包含所有 dataclass 定義：BountyProgram、ProgramScope、ScanTarget、
ScanProfile、Vulnerability、ScanProgress、ScanResult、ScanOperation、
BatchAuth、AuthDecision、CvssScore、BountyRange、Report、
WhoisVerification、ChangeEvent。
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import uuid

from app.bounty.enums import (
    AuthStatus,
    PlatformType,
    ReportStatus,
    ScanStatus,
    ScanTool,
    SeverityLevel,
    TargetType,
    TrustLevel,
)


@dataclass
class BountyProgram:
    """Bug Bounty 計畫資料模型。"""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    platform: PlatformType = PlatformType.HACKERONE
    platform_program_id: str = ""
    name: str = ""
    organization: str = ""
    domains: list[str] = field(default_factory=list)
    scope_in: list[str] = field(default_factory=list)
    scope_out: list[str] = field(default_factory=list)
    allowed_test_types: list[str] = field(default_factory=list)
    bounty_range_low: float = 0.0
    bounty_range_high: float = 0.0
    trust_score: float = 0.0
    trust_level: TrustLevel = TrustLevel.SUSPICIOUS
    active_since: Optional[datetime] = None
    public_reports_count: int = 0
    has_legal_terms: bool = False
    whois_verified: bool = False
    crawled_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        """Serialize BountyProgram to a JSON-compatible dict.

        Enum fields are converted to their value strings, datetime fields
        to ISO 8601 format strings. Optional[datetime] stays None when None.

        Returns:
            A dict that can be directly serialized with json.dumps().
        """
        return {
            "id": self.id,
            "platform": self.platform.value,
            "platform_program_id": self.platform_program_id,
            "name": self.name,
            "organization": self.organization,
            "domains": list(self.domains),
            "scope_in": list(self.scope_in),
            "scope_out": list(self.scope_out),
            "allowed_test_types": list(self.allowed_test_types),
            "bounty_range_low": self.bounty_range_low,
            "bounty_range_high": self.bounty_range_high,
            "trust_score": self.trust_score,
            "trust_level": self.trust_level.value,
            "active_since": self.active_since.isoformat() if self.active_since else None,
            "public_reports_count": self.public_reports_count,
            "has_legal_terms": self.has_legal_terms,
            "whois_verified": self.whois_verified,
            "crawled_at": self.crawled_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BountyProgram":
        """Deserialize a dict back to a BountyProgram instance.

        Enum fields are restored from value strings, datetime fields from
        ISO 8601 format strings.

        Args:
            data: A dict produced by to_dict().

        Returns:
            The restored BountyProgram instance.
        """
        return cls(
            id=data["id"],
            platform=PlatformType(data["platform"]),
            platform_program_id=data["platform_program_id"],
            name=data["name"],
            organization=data["organization"],
            domains=list(data["domains"]),
            scope_in=list(data["scope_in"]),
            scope_out=list(data["scope_out"]),
            allowed_test_types=list(data["allowed_test_types"]),
            bounty_range_low=data["bounty_range_low"],
            bounty_range_high=data["bounty_range_high"],
            trust_score=data["trust_score"],
            trust_level=TrustLevel(data["trust_level"]),
            active_since=(
                datetime.fromisoformat(data["active_since"])
                if data["active_since"] is not None
                else None
            ),
            public_reports_count=data["public_reports_count"],
            has_legal_terms=data["has_legal_terms"],
            whois_verified=data["whois_verified"],
            crawled_at=datetime.fromisoformat(data["crawled_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
        )


@dataclass
class ProgramScope:
    """計畫範圍結構化資料。"""

    domains: list[str] = field(default_factory=list)
    ip_ranges: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    allowed_tools: list[ScanTool] = field(default_factory=list)
    max_scan_rate: Optional[int] = None  # requests/second


@dataclass
class ScanTarget:
    """掃描目標。"""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    program_id: str = ""
    target_url: str = ""
    target_type: TargetType = TargetType.WEB_APP
    port: Optional[int] = None


@dataclass
class ScanProfile:
    """掃描設定檔。"""

    tools: list[ScanTool] = field(default_factory=list)
    args: dict[ScanTool, list[str]] = field(default_factory=dict)
    timeout_seconds: float = 1800.0  # 30 分鐘


@dataclass
class Vulnerability:
    """統一漏洞資料結構。"""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = ""
    cve_id: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.INFO
    title: str = ""
    description: str = ""
    affected_endpoint: str = ""
    evidence: str = ""
    tool_source: ScanTool = ScanTool.NUCLEI
    raw_output: str = ""
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    # MITRE ATT&CK 分類標記（描述此發現所屬技術類別，非攻擊）。可選。
    attack_technique_id: Optional[str] = None    # 例 "T1046"
    attack_technique_name: Optional[str] = None  # 例 "Network Service Discovery"
    attack_tactic: Optional[str] = None          # 例 "TA0007 Discovery"


@dataclass
class ScanProgress:
    """掃描進度。"""

    scan_id: str = ""
    percent_complete: float = 0.0
    vulnerabilities_found: int = 0
    estimated_remaining_seconds: float = 0.0
    current_tool: Optional[ScanTool] = None
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ScanResult:
    """掃描結果。"""

    scan_id: str = ""
    target: ScanTarget = field(default_factory=ScanTarget)
    status: ScanStatus = ScanStatus.COMPLETED
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    tools_used: list[ScanTool] = field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0


@dataclass
class ScanOperation:
    """待授權的掃描操作。"""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: ScanTarget = field(default_factory=ScanTarget)
    profile: ScanProfile = field(default_factory=ScanProfile)
    program_id: str = ""
    requested_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class BatchAuth:
    """批次授權。"""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    program_id: str = ""
    scan_types: list[ScanTool] = field(default_factory=list)
    granted_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime = field(default_factory=datetime.utcnow)
    granted_by: str = "operator"


@dataclass
class AuthDecision:
    """授權決定。"""

    operation_id: str = ""
    status: AuthStatus = AuthStatus.PENDING
    decided_at: Optional[datetime] = None
    reason: str = ""


@dataclass
class CvssScore:
    """CVSS 評分。"""

    base_score: float = 0.0
    severity_label: str = ""
    vector_string: str = ""


@dataclass
class BountyRange:
    """預估獎金範圍。"""

    min_usd: float = 0.0
    max_usd: float = 0.0
    confidence: str = "low"  # low/medium/high


@dataclass
class Report:
    """漏洞報告。"""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    vulnerability_id: str = ""
    program_id: str = ""
    platform: PlatformType = PlatformType.HACKERONE
    title: str = ""
    description: str = ""
    reproduction_steps: str = ""
    impact_assessment: str = ""
    remediation: str = ""
    cvss: CvssScore = field(default_factory=CvssScore)
    estimated_bounty: BountyRange = field(default_factory=BountyRange)
    evidence_attachments: list[str] = field(default_factory=list)
    status: ReportStatus = ReportStatus.DRAFT
    generated_at: datetime = field(default_factory=datetime.utcnow)
    llm_quality_score: float = 0.0  # 0.0~1.0
    # MITRE ATT&CK 分類標記（報告呈現用；描述發現所屬技術類別，非攻擊）。
    attack_technique_id: Optional[str] = None
    attack_technique_name: Optional[str] = None
    attack_tactic: Optional[str] = None


@dataclass
class WhoisVerification:
    """WHOIS 驗證結果。"""

    domain: str = ""
    registrant_org: str = ""
    claimed_org: str = ""
    match: bool = False
    verified_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ChangeEvent:
    """計畫變更事件。"""

    program_id: str = ""
    change_type: str = ""  # "new", "scope_update", "deactivated"
    details: str = ""
    detected_at: datetime = field(default_factory=datetime.utcnow)


# Trust_Score 計算參數
PLATFORM_WEIGHTS: dict[PlatformType, float] = {
    PlatformType.HACKERONE: 1.0,
    PlatformType.BUGCROWD: 1.0,
    PlatformType.INTIGRITI: 0.9,
    PlatformType.YESWEHACK: 0.9,
}

TRUST_SCORE_THRESHOLD: float = 0.7  # 最低可執行閾值

# Scan_Profile 預設映射
DEFAULT_PROFILES: dict[TargetType, list[ScanTool]] = {
    TargetType.WEB_APP: [ScanTool.NIKTO, ScanTool.NUCLEI],
    TargetType.NETWORK_SERVICE: [ScanTool.NMAP],
    TargetType.DATABASE_ENDPOINT: [ScanTool.SQLMAP],
}