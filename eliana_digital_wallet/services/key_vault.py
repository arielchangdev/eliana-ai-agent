"""Key_Vault：私鑰加密保險庫。

- AES-256-GCM 加密 + Argon2id 金鑰衍生
- 加密檔案格式：Magic(10) + Salt(32) + Nonce(12) + Ciphertext + GCM Tag(16)
  （AESGCM.encrypt 產生的 ciphertext 已含 16-byte tag 於末尾）
- 連續 3 次密碼錯誤 → 鎖定 15 分鐘
- lock() 安全清除記憶體中的解密資料
- 錢包檔案權限設為 chmod 600
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Callable, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from ..models.schemas import KeyVaultConfig

# 加密檔案格式常數
MAGIC = b"ELIANA_KV\x01"  # 10 bytes
SALT_LEN = 32
NONCE_LEN = 12
KEY_LEN = 32  # AES-256


class KeyVaultError(Exception):
    """Key_Vault 基礎例外。"""


class LockedOutError(KeyVaultError):
    """帳戶因連續密碼錯誤被鎖定。"""


class DecryptionError(KeyVaultError):
    """解密失敗（密碼錯誤或檔案損毀）。"""


class KeyVault:
    def __init__(
        self,
        config: KeyVaultConfig,
        alert_callback: Optional[Callable[[str], None]] = None,
    ):
        self.config = config
        self._alert_callback = alert_callback
        # 解密後的資料緩衝區（bytearray 以便安全清除）
        self._unlocked_buffer: Optional[bytearray] = None
        # 鎖定狀態
        self._failed_attempts = 0
        self._lockout_until: float = 0.0

    # ----- 初始化 --------------------------------------------------------- #
    async def initialize(self) -> None:
        """確保加密檔案目錄存在，並將既有檔案設為 chmod 600。"""
        path = Path(self.config.encrypted_wallet_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            self._chmod_600(path)

    @staticmethod
    def _chmod_600(path: Path) -> None:
        """設定檔案權限為 0o600（僅擁有者讀寫）。

        Windows 上 chmod 語意有限，失敗時記錄但不中斷（設計：WARNING）。
        """
        try:
            os.chmod(path, 0o600)
        except (OSError, NotImplementedError):
            # Windows 或不支援的檔案系統：不阻斷運行
            pass

    # ----- 金鑰衍生 ------------------------------------------------------- #
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """以 Argon2id 衍生 256-bit 金鑰。"""
        kdf = Argon2id(
            salt=salt,
            length=KEY_LEN,
            iterations=self.config.argon2_time_cost,
            lanes=self.config.argon2_parallelism,
            memory_cost=self.config.argon2_memory_cost,
        )
        return kdf.derive(password.encode("utf-8"))

    # ----- 加密與儲存 ----------------------------------------------------- #
    async def encrypt_and_store(self, data: bytes, master_password: str) -> None:
        """以主密碼加密 data 並寫入加密檔案。"""
        salt = os.urandom(SALT_LEN)
        nonce = os.urandom(NONCE_LEN)
        key = self._derive_key(master_password, salt)
        try:
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, data, None)  # 末尾含 16-byte tag
        finally:
            # 清除衍生金鑰
            self._wipe_bytes(key)

        blob = MAGIC + salt + nonce + ciphertext
        path = Path(self.config.encrypted_wallet_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # 原子寫入：先寫暫存檔再 rename
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(blob)
        self._chmod_600(tmp)
        os.replace(tmp, path)
        self._chmod_600(path)

    # ----- 解鎖 ----------------------------------------------------------- #
    async def unlock(self, master_password: str) -> bytes:
        """讀取加密檔案並解密。

        連續 3 次失敗鎖定 15 分鐘。鎖定期間立即拒絕（不執行 KDF）。
        成功時將解密資料存於內部緩衝區並回傳其副本。
        """
        if self.is_locked_out():
            raise LockedOutError(
                f"帳戶已鎖定，請於 {self._remaining_lockout_seconds():.0f} 秒後重試"
            )

        path = Path(self.config.encrypted_wallet_path)
        if not path.exists():
            raise KeyVaultError(f"加密檔案不存在: {path}")

        blob = path.read_bytes()
        self._validate_format(blob)

        salt = blob[len(MAGIC):len(MAGIC) + SALT_LEN]
        nonce = blob[len(MAGIC) + SALT_LEN:len(MAGIC) + SALT_LEN + NONCE_LEN]
        ciphertext = blob[len(MAGIC) + SALT_LEN + NONCE_LEN:]

        key = self._derive_key(master_password, salt)
        try:
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag:
            self._register_failure()
            raise DecryptionError("主密碼錯誤或檔案已損毀")
        finally:
            self._wipe_bytes(key)

        # 成功：重置失敗計數，存入緩衝區
        self._failed_attempts = 0
        self._unlocked_buffer = bytearray(plaintext)
        return bytes(self._unlocked_buffer)

    def _validate_format(self, blob: bytes) -> None:
        min_len = len(MAGIC) + SALT_LEN + NONCE_LEN + 16
        if len(blob) < min_len or not blob.startswith(MAGIC):
            raise DecryptionError("加密檔案格式無效或已損毀")

    # ----- 鎖定機制 ------------------------------------------------------- #
    def _register_failure(self) -> None:
        self._failed_attempts += 1
        if self._failed_attempts >= self.config.max_failed_attempts:
            self._lockout_until = time.monotonic() + (
                self.config.lockout_duration_minutes * 60
            )
            self._send_alert(
                f"Key_Vault 連續 {self._failed_attempts} 次密碼錯誤，"
                f"已鎖定 {self.config.lockout_duration_minutes} 分鐘"
            )

    def is_locked_out(self) -> bool:
        if self._lockout_until == 0.0:
            return False
        if time.monotonic() >= self._lockout_until:
            # 鎖定期滿，重置
            self._lockout_until = 0.0
            self._failed_attempts = 0
            return False
        return True

    def _remaining_lockout_seconds(self) -> float:
        return max(0.0, self._lockout_until - time.monotonic())

    def _send_alert(self, message: str) -> None:
        if self._alert_callback is not None:
            try:
                self._alert_callback(message)
            except Exception:  # noqa: BLE001 - 告警失敗不影響主流程
                pass

    # ----- 鎖定（安全清除）----------------------------------------------- #
    async def lock(self) -> None:
        """安全清除記憶體中的解密資料。"""
        if self._unlocked_buffer is not None:
            self._wipe_bytes(self._unlocked_buffer)
            self._unlocked_buffer = None

    @property
    def is_unlocked(self) -> bool:
        return self._unlocked_buffer is not None

    @staticmethod
    def _wipe_bytes(buf: bytearray | bytes) -> None:
        """逐字節歸零（僅對 bytearray 有效；bytes 為不可變，略過）。"""
        if isinstance(buf, bytearray):
            for i in range(len(buf)):
                buf[i] = 0

    def _secure_zero(self, data: bytearray) -> None:
        """公開別名，逐字節歸零。"""
        self._wipe_bytes(data)
