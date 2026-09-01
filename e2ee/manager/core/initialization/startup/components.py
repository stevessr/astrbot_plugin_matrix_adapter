"""Startup component construction: store, olm, verification, backups."""

from astrbot.api import logger

from .....olm import OlmMachine as _DEFAULT_OLM_MACHINE
from .....store import CryptoStore as _DEFAULT_CRYPTO_STORE
from .....verification import SASVerification
from ...compat import resolve_manager_symbol


class E2EEManagerCoreInitializationStartupComponentsMixin:
    async def _init_olm_components(self):
        """创建存储和加密机器。"""
        store_cls = resolve_manager_symbol("CryptoStore", _DEFAULT_CRYPTO_STORE)
        self._store = store_cls(
            self.store_path,
            self.user_id,
            self.device_id,
            namespace_key=self._store_namespace,
        )
        olm_cls = resolve_manager_symbol("OlmMachine", _DEFAULT_OLM_MACHINE)
        self._olm = olm_cls(self._store, self.user_id, self.device_id)

        # 上传设备密钥
        await self._upload_device_keys()

    async def _init_verification(self):
        """初始化 SAS 验证。"""

        self._verification = SASVerification(
            client=self.client,
            user_id=self.user_id,
            device_id=self.device_id,
            olm_machine=self._olm,
            store_path=self.store_path,
            namespace_key=self._store_namespace,
            auto_verify_mode=self.auto_verify_mode,
            trust_on_first_use=self.trust_on_first_use,
        )
        # Inject self into verification module to allow sending encrypted events
        self._verification.e2ee_manager = self

        logger.info(f"SAS 验证已初始化 (mode: {self.auto_verify_mode})")

    async def _init_key_backup_signing(self):
        """初始化密钥备份和交叉签名。"""
        from .....key_backup import KeyBackup
        from .....signing import CrossSigning

        self._key_backup = KeyBackup(
            self.client,
            self._store,
            self._olm,
            recovery_key=self.recovery_key,
            store_path=str(self.store_path),
        )
        self._cross_signing = CrossSigning(
            self.client,
            self.user_id,
            self.device_id,
            self._olm,
            self.password,
            secret_storage=self._key_backup,
            request_secret_from_devices=self.request_secret_from_devices,
            repair_current_device_keys=self._upload_device_keys,
            oauth_uia_callback=self.oauth_uia_callback,
            namespace_key=self._store_namespace,
        )

        await self._apply_key_backup_preference()
        await self._key_backup.initialize()
        await self._cross_signing.initialize()

        # 如果启用密钥备份，创建或使用现有备份
        if self.enable_key_backup:
            if not self._key_backup.backup_version:
                await self._key_backup.create_backup()

        # 仅当当前账户本地缺少房间密钥时才尝试恢复
        if self._key_backup.should_restore_for_session():
            logger.info("检测到本地房间密钥缺失，尝试从服务器备份恢复...")
            await self._key_backup.restore_room_keys_if_needed(reason="startup")
