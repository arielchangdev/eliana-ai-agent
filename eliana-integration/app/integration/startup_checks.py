"""真實啟動探測函式（RHEL VM 用）。

每個工廠函式回傳一個 async () -> bool 的探測，符合 StartupValidator 的注入介面
（CheckFn）。本機無法連真實服務，故這些函式的正確性以「介面 + 邏輯」單元測試
驗證（注入 fake transport）；真實連線在 VM 階段生效。

用法（VM 啟動腳本）：
    from app.integration.startup_checks import build_checks_from_config
    checks = build_checks_from_config(config_manager.config, secrets=os.environ)
    validator = StartupValidator(bus, checks)
"""
from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

import structlog

logger = structlog.get_logger(__name__)

CheckFn = Callable[[], Awaitable[bool]]

# HTTP 取得器：接收 url → 回傳 status_code。預設用 httpx，可注入 fake 供測試。
HttpGetter = Callable[[str, float], Awaitable[int]]
# TCP 探測器：接收 (host, port) → 回傳 bool（可連線）。可注入 fake 供測試。
TcpProber = Callable[[str, int, float], Awaitable[bool]]


async def _default_http_get(url: str, timeout: float) -> int:
    import httpx

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.get(url)
        return resp.status_code


async def _default_tcp_probe(host: str, port: int, timeout: float) -> bool:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return True
    except (OSError, asyncio.TimeoutError):
        return False


# --------------------------------------------------------------------------- #
# 各依賴探測工廠
# --------------------------------------------------------------------------- #
def make_ollama_check(base_url: str, timeout: float = 10.0,
                      http_get: HttpGetter | None = None) -> CheckFn:
    """Ollama：GET {base_url}/api/tags 回 200 視為可用。"""
    getter = http_get or _default_http_get

    async def check() -> bool:
        try:
            code = await getter(f"{base_url.rstrip('/')}/api/tags", timeout)
            return code == 200
        except Exception as exc:  # noqa: BLE001
            logger.warning("ollama_check_failed", error=str(exc))
            return False

    return check


def make_electrum_check(rpc_url: str, timeout: float = 5.0,
                        tcp_probe: TcpProber | None = None) -> CheckFn:
    """Electrum daemon：探測 RPC 埠可連線。"""
    prober = tcp_probe or _default_tcp_probe
    host, port = _split_host_port(rpc_url, default_port=7777)

    async def check() -> bool:
        return await prober(host, port, timeout)

    return check


def make_chromadb_check(host: str, port: int, timeout: float = 5.0,
                        http_get: HttpGetter | None = None) -> CheckFn:
    """ChromaDB: GET heartbeat returns 200 means healthy.

    New ChromaDB uses /api/v2/heartbeat, old uses /api/v1/heartbeat.
    Try v2 first, fall back to v1; any 200 passes.
    """
    getter = http_get or _default_http_get

    async def check() -> bool:
        for path in ("/api/v2/heartbeat", "/api/v1/heartbeat"):
            try:
                code = await getter(f"http://{host}:{port}{path}", timeout)
                if code == 200:
                    return True
            except Exception as exc:  # noqa: BLE001
                logger.warning("chromadb_check_failed", path=path, error=str(exc))
        return False

    return check

def make_telegram_check(bot_token: str, api_base: str = "https://api.telegram.org",
                        timeout: float = 5.0, enabled: bool = True,
                        http_get: HttpGetter | None = None) -> CheckFn:
    """Telegram：GET {api_base}/bot{token}/getMe 回 200 視為 token 有效。

    enabled=False 或無 token 時視為通過（未啟用即不阻斷）。
    """
    getter = http_get or _default_http_get

    async def check() -> bool:
        if not enabled or not bot_token:
            return True
        try:
            code = await getter(f"{api_base}/bot{bot_token}/getMe", timeout)
            return code == 200
        except Exception as exc:  # noqa: BLE001
            logger.warning("telegram_check_failed", error=str(exc))
            return False

    return check


def make_ssh_check(hostname: str, port: int = 22, timeout: float = 5.0,
                   tcp_probe: TcpProber | None = None) -> CheckFn:
    """SSH 至 Weapon_Host（Kali）：探測 SSH 埠可連線。

    僅探測 TCP 可達性，不做認證（金鑰認證在實際 SSH_Channel 建立時處理）。
    """
    prober = tcp_probe or _default_tcp_probe

    async def check() -> bool:
        return await prober(hostname, port, timeout)

    return check


# --------------------------------------------------------------------------- #
# 從設定組裝全部檢查
# --------------------------------------------------------------------------- #
def _split_host_port(url: str, default_port: int) -> tuple[str, int]:
    """從 http://host:port 或 host:port 取出 (host, port)。"""
    s = url
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]
    if ":" in s:
        host, port_s = s.rsplit(":", 1)
        try:
            return host, int(port_s)
        except ValueError:
            return host, default_port
    return s, default_port


def build_checks_from_config(
    config: dict[str, Any],
    secrets: dict[str, str] | None = None,
    *,
    http_get: HttpGetter | None = None,
    tcp_probe: TcpProber | None = None,
) -> dict[str, CheckFn]:
    """依 eliana.yaml 設定組裝五個依賴探測。

    secrets 提供敏感值（如 Telegram bot token），預設不從 config 讀。
    http_get / tcp_probe 可注入以供測試。
    """
    secrets = secrets or {}

    ollama = config.get("ollama", {})
    wallet = config.get("wallet", {})
    chroma = config.get("chromadb", {})
    telegram = config.get("telegram", {})
    weapon = config.get("hosts", {}).get("weapon_host", {})

    return {
        "ssh": make_ssh_check(
            weapon.get("hostname", "localhost"),
            int(weapon.get("ssh_port", 22)),
            tcp_probe=tcp_probe,
        ),
        "ollama": make_ollama_check(
            ollama.get("base_url", "http://127.0.0.1:11434"),
            float(ollama.get("timeout_seconds", 10.0)),
            http_get=http_get,
        ),
        "electrum": make_electrum_check(
            wallet.get("electrum_rpc_url", "http://127.0.0.1:7777"),
            tcp_probe=tcp_probe,
        ),
        "chromadb": make_chromadb_check(
            chroma.get("host", "127.0.0.1"),
            int(chroma.get("port", 8001)),
            http_get=http_get,
        ),
        "telegram": make_telegram_check(
            secrets.get("ELIANA_TELEGRAM__BOT_TOKEN", ""),
            telegram.get("api_base", "https://api.telegram.org"),
            enabled=bool(telegram.get("enabled", False)),
            http_get=http_get,
        ),
    }
