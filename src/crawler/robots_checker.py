"""robots.txt 檢查器。

- 解析 robots.txt 的 User-agent / Disallow / Allow 規則
- 依標準規範判斷路徑是否允許爬取：
  * 最長匹配規則優先（longest match wins）
  * 規則長度相同時 Allow 優先於 Disallow
  * 空 Disallow 值代表允許全部
  * 未提及的路徑預設允許
- robots.txt 不存在（HTTP 404 或抓取失敗）時預設允許
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

_WILDCARD_AGENT = "*"


@dataclass
class RobotRule:
    path: str
    allow: bool


@dataclass
class RobotsRules:
    """某 user-agent 群組的規則集合。"""

    rules: list[RobotRule] = field(default_factory=list)

    def is_allowed(self, path: str) -> bool:
        """依最長匹配規則判斷路徑是否允許。"""
        if not path:
            path = "/"
        best: Optional[RobotRule] = None
        best_len = -1
        for rule in self.rules:
            if _path_matches(rule.path, path):
                rlen = len(rule.path)
                if rlen > best_len or (
                    rlen == best_len and best is not None and rule.allow and not best.allow
                ):
                    best = rule
                    best_len = rlen
        if best is None:
            return True  # 未提及 -> 允許
        return best.allow


def _path_matches(rule_path: str, path: str) -> bool:
    """支援 `*` 萬用字元與 `$` 結尾錨點的路徑前綴匹配。"""
    if rule_path == "":
        return True  # 空規則匹配全部（通常為 Allow: 空）

    # 處理結尾錨點
    anchored = rule_path.endswith("$")
    pattern = rule_path[:-1] if anchored else rule_path

    if "*" not in pattern:
        if anchored:
            return path == pattern
        return path.startswith(pattern)

    # 含萬用字元：以 * 切段，依序前綴匹配
    segments = pattern.split("*")
    pos = 0
    for i, seg in enumerate(segments):
        if seg == "":
            continue
        idx = path.find(seg, pos)
        if idx == -1:
            return False
        if i == 0 and idx != 0:
            # 第一段必須從開頭匹配（robots 規則為路徑前綴）
            return False
        pos = idx + len(seg)
    if anchored:
        return pos == len(path)
    return True


def parse_robots_txt(content: str, user_agent: str = _WILDCARD_AGENT) -> RobotsRules:
    """解析 robots.txt 文字，回傳指定 user-agent（含 `*` 後備）的規則。

    規則收集邏輯：先嘗試匹配特定 user_agent 的群組，若無則使用 `*` 群組。
    """
    # 群組：user-agent -> list[RobotRule]，保留宣告順序
    groups: dict[str, list[RobotRule]] = {}
    current_agents: list[str] = []
    # 標記某行是否剛結束一個 user-agent 宣告區塊
    expecting_rules = False

    for raw in content.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field_name, _, value = line.partition(":")
        field_name = field_name.strip().lower()
        value = value.strip()

        if field_name == "user-agent":
            if not expecting_rules:
                # 連續多個 user-agent 宣告共用後續規則
                if not current_agents:
                    current_agents = []
                current_agents.append(value.lower())
            else:
                # 新群組開始
                current_agents = [value.lower()]
                expecting_rules = False
            groups.setdefault(value.lower(), [])
        elif field_name in ("disallow", "allow"):
            expecting_rules = True
            allow = field_name == "allow"
            # 空值的 Disallow 代表「不限制」，依標準視為無效規則跳過；
            # 空值的 Allow 代表允許全部，保留為匹配全部的規則。
            if not value and not allow:
                continue
            for agent in current_agents:
                groups.setdefault(agent, []).append(RobotRule(path=value, allow=allow))

    selected = groups.get(user_agent.lower())
    if selected is None:
        selected = groups.get(_WILDCARD_AGENT, [])
    return RobotsRules(rules=list(selected))


async def check_robots_txt(
    base_url: str,
    http_client=None,
    user_agent: str = _WILDCARD_AGENT,
) -> bool:
    """檢查 base_url 是否允許爬取。

    抓取該網域的 /robots.txt 並解析；抓取失敗或 404 時預設允許。
    可注入 http_client（httpx.AsyncClient）以利測試。
    """
    split = urlsplit(base_url)
    if not split.scheme or not split.netloc:
        return True
    robots_url = f"{split.scheme}://{split.netloc}/robots.txt"
    path = split.path or "/"

    owns_client = False
    if http_client is None:
        import httpx

        http_client = httpx.AsyncClient(timeout=10.0)
        owns_client = True

    try:
        resp = await http_client.get(robots_url)
        if resp.status_code != 200:
            return True  # 無 robots.txt -> 允許
        rules = parse_robots_txt(resp.text, user_agent)
        return rules.is_allowed(path)
    except Exception:  # noqa: BLE001 - 抓取失敗預設允許
        return True
    finally:
        if owns_client:
            await http_client.aclose()
