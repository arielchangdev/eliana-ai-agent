"""Bounty 模組列舉型別。

包含 PlatformType、ScanTool、TargetType、SeverityLevel、
AuthStatus、ScanStatus、ReportStatus、TrustLevel 等列舉定義。
"""

from enum import Enum


class PlatformType(Enum):
    """支援的 Bug Bounty 平台。"""

    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    YESWEHACK = "yeswehack"


class ScanTool(Enum):
    """支援的掃描工具。"""

    NMAP = "nmap"
    NIKTO = "nikto"
    NUCLEI = "nuclei"
    SQLMAP = "sqlmap"


class TargetType(Enum):
    """目標類型。"""

    WEB_APP = "web_app"
    NETWORK_SERVICE = "network_service"
    DATABASE_ENDPOINT = "database_endpoint"


class SeverityLevel(Enum):
    """漏洞嚴重等級。"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AuthStatus(Enum):
    """授權狀態。"""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class ScanStatus(Enum):
    """掃描狀態。"""

    QUEUED = "queued"
    AUTHORIZED = "authorized"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class ReportStatus(Enum):
    """報告狀態。"""

    DRAFT = "draft"
    REVIEWED = "reviewed"
    SUBMITTED = "submitted"


class TrustLevel(Enum):
    """計畫信任等級。"""

    VERIFIED = "verified"  # Trust_Score >= 0.8
    ACCEPTABLE = "acceptable"  # Trust_Score >= 0.6
    SUSPICIOUS = "suspicious"  # Trust_Score < 0.6
    USER_VERIFIED = "user_verified"  # 使用者自行驗證