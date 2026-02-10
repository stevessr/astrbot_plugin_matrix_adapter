"""
Key Backup - Matrix 密钥备份

实现 Megolm 会话密钥的服务器端备份和恢复。
使用用户配置的恢复密钥进行加密。
"""

from pathlib import Path

from astrbot.api import logger

from ..constants import CRYPTO_KEY_SIZE_32, HKDF_MEGOLM_BACKUP_INFO
from .key_backup_backup import KeyBackupBackupMixin
from .key_backup_crypto import _compute_hkdf, _decode_recovery_key
from .key_backup_ssss import KeyBackupSSSSMixin


class KeyBackup(KeyBackupSSSSMixin, KeyBackupBackupMixin):
    """
    密钥备份管理器

    使用用户配置的恢复密钥进行加密，支持：
    - 创建密钥备份
    - 上传 Megolm 会话密钥到备份
    - 从备份恢复密钥
    """

    def __init__(
        self,
        client,
        crypto_store,
        olm_machine,
        recovery_key: str = "",
        store_path: str | Path = "",
    ):
        """
        初始化密钥备份

        Args:
            client: MatrixHTTPClient
            crypto_store: CryptoStore
            olm_machine: OlmMachine
            recovery_key: 用户配置密钥（默认按 Secret Storage Key 处理）
            store_path: 存储路径（用于持久化提取的备份密钥）
        """
        self.client = client
        self.store = crypto_store
        self.olm = olm_machine
        self.store_path = store_path

        self._backup_version: str | None = None
        self._backup_auth_data: dict = {}
        self._recovery_key_bytes: bytes | None = None
        self._encryption_key: bytes | None = None
        self._original_recovery_key_str: str = recovery_key  # 保存原始输入
        self._provided_secret_storage_key_bytes: bytes | None = None
        self._last_restore_attempt_ts: float = 0.0
        self._restore_cooldown_sec: float = 60.0

        # 处理用户提供的恢复密钥
        if recovery_key:
            try:
                # Treat configured key as Secret Storage key by default.
                # It can still be used as a direct backup key as fallback.
                self._provided_secret_storage_key_bytes = _decode_recovery_key(
                    recovery_key
                )
                logger.info("已加载用户配置密钥（默认按 Secret Storage Key 处理）")
            except Exception as e:
                logger.error(f"解析恢复密钥失败：{e}")

    def _get_extracted_key_path(self) -> str:
        """获取提取的备份密钥存储路径"""
        if self.store_path:
            return str(Path(self.store_path) / "extracted_backup_key.bin")
        return ""

    def _save_extracted_key(self, key_bytes: bytes):
        """保存从 SSSS 提取的备份密钥到本地"""
        try:
            path = self._get_extracted_key_path()
            if not path:
                return

            Path(path).parent.mkdir(parents=True, exist_ok=True)

            with open(path, "wb") as f:
                f.write(key_bytes)

            logger.info(f"已保存提取的备份密钥到 {path}")
        except Exception as e:
            logger.warning(f"保存提取的备份密钥失败：{e}")

    def _load_extracted_key(self) -> bytes | None:
        """从本地加载之前提取的备份密钥"""
        try:
            path = self._get_extracted_key_path()
            if not path:
                return None

            if not Path(path).exists():
                return None

            with open(path, "rb") as f:
                key_bytes = f.read()

            if len(key_bytes) == CRYPTO_KEY_SIZE_32:
                logger.info("从本地加载了提取的备份密钥")
                return key_bytes
            else:
                logger.warning(f"本地备份密钥长度不正确：{len(key_bytes)} bytes")
                return None
        except Exception as e:
            logger.debug(f"加载提取的备份密钥失败：{e}")
            return None

    def use_recovery_key_bytes(self, key_bytes: bytes, persist: bool = False) -> bool:
        """Set current backup key bytes and derive encryption key."""
        if not key_bytes or len(key_bytes) != CRYPTO_KEY_SIZE_32:
            return False
        self._recovery_key_bytes = key_bytes
        self._encryption_key = _compute_hkdf(
            self._recovery_key_bytes, b"", HKDF_MEGOLM_BACKUP_INFO
        )
        if persist:
            self._save_extracted_key(key_bytes)
        return True

    def has_local_room_keys(self) -> bool:
        """Whether current account already has inbound Megolm keys locally."""
        try:
            return self.store.get_megolm_inbound_count() > 0
        except Exception:
            return bool(getattr(self.store, "_megolm_inbound", {}))

    def can_attempt_restore(self) -> bool:
        """Whether backup restore can be attempted with current state."""
        return bool(self._backup_version and self._recovery_key_bytes)

    def should_restore_for_missing_keys(self) -> bool:
        """Only restore when this account is missing local keys."""
        return self.can_attempt_restore() and not self.has_local_room_keys()
