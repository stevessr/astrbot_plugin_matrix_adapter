"""
E2EE Manager - 端到端加密管理器

整合 OlmMachine 和 HTTP 客户端，提供高层 E2EE 操作接口。
"""

from pathlib import Path
from typing import Literal

from astrbot.api import logger

from ..storage_paths import MatrixStoragePaths
from .crypto_store import CryptoStore
from .e2ee_manager_decrypt import E2EEManagerDecryptMixin
from .e2ee_manager_keys import E2EEManagerKeysMixin
from .e2ee_manager_requests import E2EEManagerRequestsMixin
from .e2ee_manager_sessions import E2EEManagerSessionsMixin
from .e2ee_manager_verification import E2EEManagerVerificationMixin
from .olm_machine import VODOZEMAC_AVAILABLE, OlmMachine


class E2EEManager(
    E2EEManagerVerificationMixin,
    E2EEManagerKeysMixin,
    E2EEManagerDecryptMixin,
    E2EEManagerRequestsMixin,
    E2EEManagerSessionsMixin,
):
    """
    端到端加密管理器

    负责：
    - 初始化加密组件
    - 设备密钥上传
    - 消息加密/解密
    - 密钥交换
    - SAS 设备验证
    - 密钥备份
    - 交叉签名
    """

    def __init__(
        self,
        client,
        user_id: str,
        device_id: str,
        store_path: str | Path,
        homeserver: str,
        auto_verify_mode: Literal[
            "auto_accept", "auto_reject", "manual"
        ] = "auto_accept",
        enable_key_backup: bool = False,
        recovery_key: str = "",
        trust_on_first_use: bool = False,
        password: str | None = None,
    ):
        """
        初始化 E2EE 管理器

        Args:
            client: MatrixHTTPClient 实例
            user_id: 用户 ID
            device_id: 设备 ID
            store_path: 加密存储基础路径
            homeserver: Matrix 服务器 URL
            auto_verify_mode: 自动验证模式 (auto_accept/auto_reject/manual)
            enable_key_backup: 是否启用密钥备份
            recovery_key: 用户配置的恢复密钥 (base64)
            trust_on_first_use: 是否自动信任首次使用的设备
            password: 用户密码 (可选，用于 UIA)
        """
        self.client = client
        self.user_id = user_id
        self.device_id = device_id
        self.homeserver = homeserver
        self.password = password

        # 使用 MatrixStoragePaths 生成用户存储目录
        self.store_path = MatrixStoragePaths.get_user_storage_dir(
            str(store_path), homeserver, user_id
        )

        # Ensure the directory exists
        MatrixStoragePaths.ensure_directory(self.store_path)
        self.auto_verify_mode = auto_verify_mode
        self.enable_key_backup = enable_key_backup
        self.recovery_key = recovery_key
        self.trust_on_first_use = trust_on_first_use

        self._store: CryptoStore | None = None
        self._olm: OlmMachine | None = None
        self._verification = None  # SASVerification
        self._key_backup = None  # KeyBackup
        self._cross_signing = None  # CrossSigning
        self._initialized = False

    @property
    def is_available(self) -> bool:
        """检查 E2EE 是否可用"""
        return VODOZEMAC_AVAILABLE

    async def initialize(self):
        """初始化 E2EE 组件"""
        if not VODOZEMAC_AVAILABLE:
            logger.warning("vodozemac 未安装，E2EE 功能不可用")
            return False

        try:
            # 创建存储和加密机器
            self._store = CryptoStore(self.store_path, self.user_id, self.device_id)
            self._olm = OlmMachine(self._store, self.user_id, self.device_id)

            # 上传设备密钥
            await self._upload_device_keys()

            # 初始化 SAS 验证
            from .verification import SASVerification

            self._verification = SASVerification(
                client=self.client,
                user_id=self.user_id,
                device_id=self.device_id,
                olm_machine=self._olm,
                store_path=self.store_path,
                auto_verify_mode=self.auto_verify_mode,
                trust_on_first_use=self.trust_on_first_use,
            )
            # Inject self into verification module to allow sending encrypted events
            self._verification.e2ee_manager = self

            logger.info(f"SAS 验证已初始化 (mode: {self.auto_verify_mode})")

            # 初始化密钥备份和交叉签名
            from .cross_signing import CrossSigning
            from .key_backup import KeyBackup

            self._key_backup = KeyBackup(
                self.client,
                self._store,
                self._olm,
                recovery_key=self.recovery_key,
                store_path=str(self.store_path),
            )
            self._cross_signing = CrossSigning(
                self.client, self.user_id, self.device_id, self._olm, self.password
            )

            await self._key_backup.initialize()
            await self._cross_signing.initialize()

            # 如果启用密钥备份，创建或使用现有备份
            if self.enable_key_backup:
                if not self._key_backup._backup_version:
                    await self._key_backup.create_backup()

            # 始终尝试从备份恢复密钥（如果有配置恢复密钥）
            if self._key_backup._backup_version and self.recovery_key:
                logger.info("尝试从服务器备份恢复密钥...")
                await self._key_backup.restore_room_keys()

            # 自动签名自己的设备（使设备变为"已验证"状态）
            if self._cross_signing._master_key:
                await self._cross_signing.sign_device(self.device_id)
                logger.info(f"已自动签名设备：{self.device_id}")
            else:
                # 如果没有交叉签名密钥，尝试上传
                try:
                    await self._cross_signing.upload_cross_signing_keys()
                    await self._cross_signing.sign_device(self.device_id)
                    logger.info(f"已上传交叉签名密钥并签名设备：{self.device_id}")
                except Exception as e:
                    logger.warning(f"上传交叉签名密钥失败（可能需要 UIA）：{e}")

            self._initialized = True
            logger.info(f"E2EE 初始化成功 (device_id: {self.device_id})")

            # 初始化完成后，尝试为自己的未验证设备发起验证
            await self._verify_untrusted_own_devices()

            return True

        except Exception as e:
            logger.error(f"E2EE 初始化失败：{e}")
            return False
