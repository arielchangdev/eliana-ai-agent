"""MITRE ATT&CK 對應（分類與標記，非攻擊執行）。

本模組把「已授權掃描的既有發現」歸類到 ATT&CK 戰術/技術，純粹是報告的
專業分類層：描述「這個發現屬於哪一種技術類別」，不是規劃或執行攻擊。
對應到如 T1190（Exploit Public-Facing Application）等技術，意思是「此發現
若被利用時所對應的 ATT&CK 技術分類」——標準紅隊報告做法，agent 不執行利用。

設計（比照 scanner._EVAL_MODE_ARGS 的白名單風格）：
  * _ATTACK_RULES 是唯一的對應來源，規則化、可一眼稽核。
  * 每條規則標明：工具來源 + 關鍵字條件 → (技術編號, 技術名, 戰術編號, 戰術名)。
  * 純函式對應，無副作用、無外部網路（離線內建表）。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.bounty.enums import ScanTool


@dataclass(frozen=True)
class AttackTechnique:
    """一個 ATT&CK 技術分類標記（描述發現所屬類別，非攻擊指令）。"""
    technique_id: str      # 例 "T1046"
    technique_name: str    # 例 "Network Service Discovery"
    tactic_id: str         # 例 "TA0007"
    tactic_name: str       # 例 "Discovery"


# --------------------------------------------------------------------------- #
# ATT&CK 對應白名單（唯一來源，可稽核）
# --------------------------------------------------------------------------- #
# 常用技術/戰術的具名常數（避免散落字串、便於稽核與重用）。
_T = {
    "network_service_discovery": AttackTechnique(
        "T1046", "Network Service Discovery", "TA0007", "Discovery"),
    "gather_host_info": AttackTechnique(
        "T1592", "Gather Victim Host Information", "TA0043", "Reconnaissance"),
    "gather_host_software": AttackTechnique(
        "T1592.002", "Gather Victim Host Information: Software",
        "TA0043", "Reconnaissance"),
    "gather_network_info": AttackTechnique(
        "T1590", "Gather Victim Network Information", "TA0043", "Reconnaissance"),
    "gather_network_appliances": AttackTechnique(
        "T1590.004", "Gather Victim Network Information: Network Security Appliances",
        "TA0043", "Reconnaissance"),
    "active_scanning": AttackTechnique(
        "T1595", "Active Scanning", "TA0043", "Reconnaissance"),
    "wordlist_scanning": AttackTechnique(
        "T1595.003", "Active Scanning: Wordlist Scanning",
        "TA0043", "Reconnaissance"),
    "file_dir_discovery": AttackTechnique(
        "T1083", "File and Directory Discovery", "TA0007", "Discovery"),
    "exploit_public_app": AttackTechnique(
        "T1190", "Exploit Public-Facing Application", "TA0001", "Initial Access"),
    "xss_javascript": AttackTechnique(
        "T1059.007", "Command and Scripting Interpreter: JavaScript",
        "TA0002", "Execution"),
    "weak_encryption_config": AttackTechnique(
        "T1600", "Weaken Encryption", "TA0005", "Defense Evasion"),
}

# 細化規則：(tool_source, 必含關鍵字 tuple) -> 技術。先比對細規則（關鍵字），
# 命中則用之；否則落到該工具的預設技術（_TOOL_DEFAULT）。
# 關鍵字對 title + description 做小寫子字串比對（全部命中才算）。
_ATTACK_RULES: list[tuple[Optional[ScanTool], tuple[str, ...], AttackTechnique]] = [
    # nmap：開放 port/service -> 服務探索；banner/版本 -> 主機資訊收集
    (ScanTool.NMAP, ("open port",), _T["network_service_discovery"]),
    (ScanTool.NMAP, ("banner",), _T["gather_host_info"]),
    (ScanTool.NMAP, ("ssh2-enum",), _T["gather_host_info"]),
    # 跨工具關鍵字（工具不限）：具體弱點類型的分類標記
    (None, ("sql injection",), _T["exploit_public_app"]),
    (None, ("sqli",), _T["exploit_public_app"]),
    (None, ("xss",), _T["xss_javascript"]),
    (None, ("cross-site scripting",), _T["xss_javascript"]),
    (None, ("remote code", ), _T["exploit_public_app"]),
    (None, ("rce",), _T["exploit_public_app"]),
    (None, ("directory listing",), _T["file_dir_discovery"]),
    (None, ("directory traversal",), _T["file_dir_discovery"]),
]

# 每個工具的預設技術分類（當細規則未命中時使用）。
_TOOL_DEFAULT: dict[ScanTool, AttackTechnique] = {
    ScanTool.NMAP: _T["network_service_discovery"],
    ScanTool.DNSRECON: _T["gather_network_info"],
    ScanTool.WHATWEB: _T["gather_host_software"],
    ScanTool.WAFW00F: _T["gather_network_appliances"],
    ScanTool.GOBUSTER: _T["file_dir_discovery"],
    ScanTool.SSLSCAN: _T["weak_encryption_config"],
    ScanTool.NIKTO: _T["exploit_public_app"],
    ScanTool.NUCLEI: _T["exploit_public_app"],
    # SQLMAP 的解析器保留供人類操作者匯入；若有此類發現，分類為對外應用利用。
    ScanTool.SQLMAP: _T["exploit_public_app"],
}


def map_finding_to_attack(
    tool_source: ScanTool, title: str = "", description: str = "",
) -> Optional[AttackTechnique]:
    """把一個發現分類到 ATT&CK 技術（純函式；分類標記，非攻擊）。

    先用「工具來源 + 關鍵字」細規則比對；未命中則用該工具的預設技術分類。
    完全無法分類時回 None（誠實：不硬塞）。
    """
    text = f"{title or ''} {description or ''}".lower()

    for rule_tool, keywords, tech in _ATTACK_RULES:
        if rule_tool is not None and rule_tool != tool_source:
            continue
        if all(kw in text for kw in keywords):
            return tech

    return _TOOL_DEFAULT.get(tool_source)
