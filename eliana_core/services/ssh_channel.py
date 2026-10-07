"""SSH 安全通訊通道，基於 asyncssh。"""

import asyncio
import logging
import random
import time
from datetime import datetime, timezone
from typing import Optional

import asyncssh

from eliana_core.models.remote import RemoteResult
from eliana_core.models.task import HostTarget
from eliana_core.errors.exceptions import SSHConnectionError, SSHAuthenticationError

logger = logging.getLogger(__name__)


class SSHChannel:
    """SSH 安全通訊通道，基於 asyncssh。

    使用 Ed25519 金鑰認證建立加密連線至 Weapon_Host，
    支援遠端指令執行、SFTP 檔案傳輸及健康狀態檢查。
    """

    # Session key 輪替間隔（24 小時）
    KEY_ROTATION_INTERVAL_SECONDS: float = 24 * 60 * 60

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str = "root",
        private_key_path: str = "~/.ssh/id_ed25519",
        known_hosts_path: Optional[str] = None,
        connect_timeout: float = 5.0,
    ):
        """初始化 SSH 通道。

        Args:
            host: 目標主機位址（Weapon_Host）。
            port: SSH 連接埠。
            username: 登入使用者名稱。
            private_key_path: Ed25519 私鑰路徑。
            known_hosts_path: known_hosts 檔案路徑，None 則不驗證。
            connect_timeout: 連線逾時秒數（預設 5 秒，符合需求 3.3）。
        """
        self._host = host
        self._port = port
        self._username = username
        self._private_key_path = private_key_path
        self._known_hosts_path = known_hosts_path
        self._connect_timeout = connect_timeout
        self._connection: Optional[asyncssh.SSHClientConnection] = None
        self._last_key_rotation: Optional[datetime] = None

    @property
    def is_connected(self) -> bool:
        """檢查連線是否已建立且未關閉。"""
        return self._connection is not None

    async def connect(self) -> None:
        """建立 SSH 連線，使用 Ed25519 金鑰認證。

        - 僅允許 Ed25519 金鑰認證，禁止密碼認證（需求 3.1）
        - 指定加密演算法為 AES-256-GCM 或 ChaCha20-Poly1305（需求 3.2）
        - 連線需在 5 秒內建立（需求 3.3）

        Raises:
            SSHAuthenticationError: 金鑰認證失敗。
            SSHConnectionError: 連線逾時或網路錯誤。
        """
        try:
            # 載入 Ed25519 私鑰
            private_key = asyncssh.read_private_key(self._private_key_path)

            # 設定 known_hosts，None 表示不驗證（開發環境）
            known_hosts = self._known_hosts_path if self._known_hosts_path else None

            # 建立連線，禁止密碼認證，僅允許公鑰認證
            self._connection = await asyncio.wait_for(
                asyncssh.connect(
                    host=self._host,
                    port=self._port,
                    username=self._username,
                    client_keys=[private_key],
                    known_hosts=known_hosts,
                    # 禁止密碼認證（需求 3.1）
                    password=None,
                    # 指定加密演算法（需求 3.2）
                    encryption_algs=[
                        "aes256-gcm@openssh.com",
                        "chacha20-poly1305@openssh.com",
                    ],
                    # 指定金鑰類型為 Ed25519
                    signature_algs=["ssh-ed25519"],
                ),
                timeout=self._connect_timeout,
            )
            # 記錄首次 key rotation 時間為連線建立時
            self._last_key_rotation = datetime.now(timezone.utc)

        except asyncio.TimeoutError:
            raise SSHConnectionError(
                f"SSH 連線逾時：無法在 {self._connect_timeout} 秒內連線至 "
                f"{self._host}:{self._port}"
            )
        except asyncssh.PermissionDenied as e:
            # 認證失敗：記錄安全事件並拒絕連線（需求 3.4，不可重試）
            logger.critical(
                "SSH 認證失敗 [安全事件]: Ed25519 金鑰驗證被拒絕 - "
                "host=%s, port=%d, user=%s, error=%s",
                self._host, self._port, self._username, e,
            )
            raise SSHAuthenticationError(
                f"SSH 認證失敗：Ed25519 金鑰驗證被拒絕 - {e}"
            )
        except asyncssh.KeyImportError as e:
            # 金鑰載入失敗也視為認證失敗（需求 3.4，不可重試）
            logger.critical(
                "SSH 金鑰載入失敗 [安全事件]: 無法讀取 Ed25519 私鑰 - "
                "key_path=%s, error=%s",
                self._private_key_path, e,
            )
            raise SSHAuthenticationError(
                f"SSH 金鑰載入失敗：無法讀取 Ed25519 私鑰 - {e}"
            )
        except (OSError, asyncssh.DisconnectError, asyncssh.ConnectionLost) as e:
            raise SSHConnectionError(
                f"SSH 連線失敗：{self._host}:{self._port} - {e}"
            )

    async def reconnect(
        self, max_retries: int = -1, interval: float = 30.0
    ) -> bool:
        """重新建立連線，支援指數退避與 jitter。

        每 30 秒嘗試重連（需求 1.5），使用指數退避策略避免
        thundering herd 效應。認證失敗時立即放棄（不可重試，需求 3.4）。

        Args:
            max_retries: 最大重試次數，-1 表示無限重試。
            interval: 基礎重試間隔秒數（預設 30 秒）。

        Returns:
            bool: 重連成功回傳 True，達到最大重試次數或認證失敗回傳 False。
        """
        max_interval = 300.0  # 最大退避間隔 5 分鐘
        attempt = 0

        # 先關閉現有連線
        await self.close()

        logger.info(
            "開始重連至 %s:%d (max_retries=%d, interval=%.1fs)",
            self._host, self._port, max_retries, interval,
        )

        while max_retries == -1 or attempt < max_retries:
            attempt += 1

            try:
                await self.connect()
                logger.info(
                    "重連成功：%s:%d（第 %d 次嘗試）",
                    self._host, self._port, attempt,
                )
                return True

            except SSHAuthenticationError as e:
                # 認證失敗：記錄安全事件，不可重試（需求 3.4）
                logger.critical(
                    "重連中止 [安全事件]: 認證失敗不可重試 - "
                    "host=%s, port=%d, attempt=%d, error=%s",
                    self._host, self._port, attempt, e.message,
                )
                return False

            except SSHConnectionError as e:
                # 連線錯誤：可重試，使用指數退避
                # 計算退避間隔：base * 2^(attempt-1)，上限 max_interval
                backoff = min(interval * (2 ** (attempt - 1)), max_interval)
                # 加入 jitter（0.5x ~ 1.5x）避免 thundering herd
                jitter = backoff * (0.5 + random.random())
                wait_time = min(jitter, max_interval)

                logger.warning(
                    "重連失敗（第 %d 次嘗試），%.1f 秒後重試 - "
                    "host=%s, error=%s",
                    attempt, wait_time, self._host, e.message,
                )

                await asyncio.sleep(wait_time)

        logger.error(
            "重連放棄：已達最大重試次數 %d - host=%s:%d",
            max_retries, self._host, self._port,
        )
        return False

    async def rotate_session_key(self) -> None:
        """輪替 session key（每 24 小時觸發，需求 3.5）。

        透過重新建立 SSH 連線來輪替 session key，
        確保金鑰洩漏風險降低。

        Raises:
            SSHConnectionError: 重連失敗。
            SSHAuthenticationError: 認證失敗。
        """
        logger.info(
            "觸發 session key 輪替 - host=%s, 上次輪替=%s",
            self._host, self._last_key_rotation,
        )

        # 關閉現有連線
        await self.close()

        # 重新建立連線（使用新的 session key）
        try:
            await self.connect()
            self._last_key_rotation = datetime.now(timezone.utc)
            logger.info(
                "Session key 輪替完成 - host=%s, 新輪替時間=%s",
                self._host, self._last_key_rotation,
            )
        except (SSHConnectionError, SSHAuthenticationError):
            logger.error(
                "Session key 輪替失敗 - host=%s", self._host,
            )
            raise

    def needs_key_rotation(self) -> bool:
        """檢查是否需要進行 session key 輪替。

        Returns:
            bool: 距上次輪替超過 24 小時回傳 True。
        """
        if self._last_key_rotation is None:
            return False
        elapsed = (
            datetime.now(timezone.utc) - self._last_key_rotation
        ).total_seconds()
        return elapsed >= self.KEY_ROTATION_INTERVAL_SECONDS

    async def execute_remote(
        self, command: str, timeout: float = 5.0
    ) -> RemoteResult:
        """在 Weapon_Host 執行指令並回傳結果。

        Args:
            command: 要在遠端執行的指令。
            timeout: 指令執行逾時秒數（預設 5 秒）。

        Returns:
            RemoteResult: 包含 stdout、stderr、exit_code 及執行時間。

        Raises:
            SSHConnectionError: 連線尚未建立或已中斷。
        """
        if not self.is_connected:
            raise SSHConnectionError("SSH 連線尚未建立，請先呼叫 connect()")

        start_time = time.perf_counter()

        try:
            result = await asyncio.wait_for(
                self._connection.run(command, check=False),
                timeout=timeout,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000

            return RemoteResult(
                stdout=result.stdout or "",
                stderr=result.stderr or "",
                exit_code=result.exit_status if result.exit_status is not None else -1,
                execution_time_ms=elapsed_ms,
            )

        except asyncio.TimeoutError:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return RemoteResult(
                stdout="",
                stderr=f"指令執行逾時（{timeout} 秒）",
                exit_code=-1,
                execution_time_ms=elapsed_ms,
            )
        except (asyncssh.DisconnectError, asyncssh.ConnectionLost) as e:
            self._connection = None
            raise SSHConnectionError(
                f"SSH 連線中斷：指令執行期間連線遺失 - {e}"
            )

    async def transfer_file(self, local_path: str, remote_path: str) -> bool:
        """透過 SFTP 傳輸檔案至 Weapon_Host。

        Args:
            local_path: 本地檔案路徑。
            remote_path: 遠端目標路徑。

        Returns:
            bool: 傳輸成功回傳 True，否則 False。

        Raises:
            SSHConnectionError: 連線尚未建立或已中斷。
        """
        if not self.is_connected:
            raise SSHConnectionError("SSH 連線尚未建立，請先呼叫 connect()")

        try:
            async with self._connection.start_sftp_client() as sftp:
                await sftp.put(local_path, remote_path)
            return True

        except (asyncssh.SFTPError, asyncssh.SFTPFailure) as e:
            # SFTP 操作失敗（權限、路徑不存在等）
            return False
        except (asyncssh.DisconnectError, asyncssh.ConnectionLost) as e:
            self._connection = None
            raise SSHConnectionError(
                f"SSH 連線中斷：檔案傳輸期間連線遺失 - {e}"
            )
        except OSError:
            # 本地檔案讀取失敗
            return False

    async def health_check(self) -> bool:
        """檢查 SSH 連線健康狀態。

        透過執行簡單指令驗證連線仍然有效。

        Returns:
            bool: 連線健康回傳 True，否則 False。
        """
        if not self.is_connected:
            return False

        try:
            result = await self.execute_remote("echo ok", timeout=3.0)
            return result.exit_code == 0 and result.stdout.strip() == "ok"
        except (SSHConnectionError, Exception):
            return False

    async def close(self) -> None:
        """關閉 SSH 連線。"""
        if self._connection is not None:
            self._connection.close()
            self._connection = None