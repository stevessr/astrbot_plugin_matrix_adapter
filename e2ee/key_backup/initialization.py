"""Key-backup manager initialization."""

from pathlib import Path

from astrbot.api import logger

from ..backup.crypto_utils import _decode_recovery_key


class KeyBackupInitializationMixin:
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
            recovery_key: 用户配置密钥（优先作为脱水/备份恢复材料，兼容 Secret Storage Key）
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
        self._provided_recovery_material_bytes: bytes | None = None
        self._provided_secret_storage_key_bytes: bytes | None = None
        self._last_restore_attempt_ts: float = 0.0
        self._restore_cooldown_sec: float = 60.0

        # 处理用户提供的恢复密钥
        if recovery_key:
            try:
                decoded_key = _decode_recovery_key(recovery_key)
                self._provided_recovery_material_bytes = decoded_key
                # Keep exposing the same key bytes to SSSS helpers as a compatibility fallback.
                self._provided_secret_storage_key_bytes = decoded_key
                logger.info(
                    "已加载用户配置密钥（优先用于脱水/备份恢复，兼容 Secret Storage Key）"
                )
            except Exception as e:
                logger.error(f"解析恢复密钥失败：{e}")
