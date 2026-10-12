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
    """支援的掃描工具。

    全部以「評估模式」使用（偵察/列舉/漏洞偵測），不含漏洞利用。
    SQLMAP 的解析器保留供人類操作者手動匯入結果，但不納入 agent 自動
    編排（見 scanner._AUTO_ORCHESTRATION_TOOLS）——利用驗證由授權人類執行。
    """

    # --- 評估/偵察（agent 自動編排）---
    NMAP = "nmap"            # port/service 偵察（safe/default scripts）
    NIKTO = "nikto"          # web server 配置掃描
    NUCLEI = "nuclei"        # 模板化漏洞偵測
    WHATWEB = "whatweb"      # 技術指紋辨識
    WAFW00F = "wafw00f"      # WAF 偵測
    DNSRECON = "dnsrecon"    # DNS 記錄被動查詢
    SSLSCAN = "sslscan"      # TLS/SSL 配置檢查
    GOBUSTER = "gobuster"    # 目錄/路徑唯讀列舉
    # --- 利用驗證（不自動編排；由授權人類操作者執行）---
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