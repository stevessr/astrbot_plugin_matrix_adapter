"""Initialization and trust setup for the high-level E2EE manager."""

import asyncio
from pathlib import Path
from typing import Literal

from astrbot.api import logger

from ....storage.backend import (
    build_folder_namespace as _DEFAULT_BUILD_FOLDER_NAMESPACE,
)
from ....storage.paths import MatrixStoragePaths as _DEFAULT_MATRIX_STORAGE_PATHS
from ...constants import (
    DEFAULT_OLM_RECOVERY_RETRY_SEC,
    DEFAULT_PROACTIVE_KEY_SHARE_INTERVAL_SEC,
    DEFAULT_ROOM_KEY_REQUEST_EXPIRY_SEC,
    DEFAULT_ROOM_KEY_REQUEST_RETRY_SEC,
    DEFAULT_ROOM_MEMBER_CACHE_TTL_SEC,
)
from ...olm import OlmMachine
from ...olm import OlmMachine as _DEFAULT_OLM_MACHINE
from ...store import CryptoStore
from ...store import CryptoStore as _DEFAULT_CRYPTO_STORE
from .compat import resolve_manager_symbol, resolve_plugin_config, vodozemac_available


class E2EEManagerCoreInitializationMixin:
    """初始化 E2EE 组件并完成本机信任配置。"""

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
        proactive_key_exchange: bool = False,
        key_maintenance_interval: int = 60,
        otk_threshold_ratio: int = 33,
        key_share_check_interval: int = 0,
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
            proactive_key_exchange: 是否启用主动密钥交换
            key_maintenance_interval: 一次性密钥自动补充的最小间隔（秒）
            otk_threshold_ratio: 触发一次性密钥补充的服务器密钥数量比例（百分比）
            key_share_check_interval: Periodic room-key distribution interval in
                seconds. Zero selects event-driven lazy mode unless proactive key
                exchange is enabled, in which case a 30-second interval is used.
        """
        self.client = client
        self.user_id = user_id
        self.device_id = device_id
        self.homeserver = homeserver
        self.password = password

        # 使用 MatrixStoragePaths 生成用户存储目录
        self._store_base_path = Path(store_path)
        storage_paths = resolve_manager_symbol(
            "MatrixStoragePaths",
            _DEFAULT_MATRIX_STORAGE_PATHS,
        )
        self.store_path = storage_paths.get_user_storage_dir(
            str(self._store_base_path), homeserver, user_id
        )
        build_namespace = resolve_manager_symbol(
            "build_folder_namespace",
            _DEFAULT_BUILD_FOLDER_NAMESPACE,
        )
        self._store_namespace = build_namespace(self.store_path, self._store_base_path)

        # Ensure the directory exists
        storage_paths.ensure_directory(self.store_path, treat_as_file=False)
        self.auto_verify_mode = auto_verify_mode
        self.enable_key_backup = enable_key_backup
        self.recovery_key = recovery_key
        self.trust_on_first_use = trust_on_first_use

        # 密钥交换积极性配置
        self.proactive_key_exchange = proactive_key_exchange
        self.key_maintenance_interval = key_maintenance_interval
        self.otk_threshold_ratio = max(1, min(100, otk_threshold_ratio))
        self.key_share_check_interval = max(0, key_share_check_interval)
        if self.proactive_key_exchange and self.key_share_check_interval == 0:
            self.key_share_check_interval = DEFAULT_PROACTIVE_KEY_SHARE_INTERVAL_SEC
        plugin_config = resolve_plugin_config()
        self.storage_backend_config = plugin_config.storage_backend_config
        self.data_storage_backend = self.storage_backend_config.backend
        self.pgsql_dsn = self.storage_backend_config.pgsql_dsn
        self.pgsql_schema = self.storage_backend_config.pgsql_schema
        self.pgsql_table_prefix = self.storage_backend_config.pgsql_table_prefix

        self._store: CryptoStore | None = None
        self._olm: OlmMachine | None = None
        self._verification = None  # SASVerification
        self._key_backup = None  # KeyBackup
        self._cross_signing = None  # CrossSigning
        self._initialized = False
        self._closing = False
        # session_id -> {"@user:server|DEVICEID", ...}
        self._room_key_share_cache: dict[str, set[str]] = {}
        # A single distribution pass per Megolm session prevents duplicate
        # /keys/claim and to-device sends from periodic and event-driven paths.
        self._room_key_share_locks: dict[str, asyncio.Lock] = {}
        # room_id -> (members, monotonic timestamp)
        self._room_members_cache: dict[str, tuple[list[str], float]] = {}
        self._room_members_cache_ttl_sec = DEFAULT_ROOM_MEMBER_CACHE_TTL_SEC
        self._room_history_visibility: dict[str, str] = {}
        self._room_encryption_config: dict[str, dict] = {}
        # throttle one-time key maintenance to avoid frequent uploads
        self._last_otk_maintenance_ts = 0.0
        # 定期密钥分发检查的任务和锁
        self._key_share_check_task: asyncio.Task | None = None
        self._key_share_check_lock = asyncio.Lock()
        # Missing-session requests reuse their Matrix request ID and are throttled.
        self._pending_room_key_requests: dict[tuple[str, str], dict] = {}
        self._room_key_request_lock = asyncio.Lock()
        self._room_key_request_retry_interval_sec = DEFAULT_ROOM_KEY_REQUEST_RETRY_SEC
        self._room_key_request_expiry_sec = DEFAULT_ROOM_KEY_REQUEST_EXPIRY_SEC
        # m.no_olm MUST be emitted only once per failed peer until an Olm send
        # succeeds. Incoming recovery attempts are independently rate-limited.
        self._no_olm_withheld_sent: set[tuple[str, str]] = set()
        self._olm_recovery_attempts: dict[tuple[str, str], float] = {}
        self._olm_recovery_retry_interval_sec = DEFAULT_OLM_RECOVERY_RETRY_SEC
        self._room_key_withheld: dict[tuple[str, str, str], dict] = {}

    async def _finalize_own_device_trust(self, log_prefix: str) -> None:
        if not self._cross_signing or not self._cross_signing.has_master_key:
            return

        device_signed = await self._cross_signing.sign_device(self.device_id)
        master_signed = await self._cross_signing.sign_master_key_with_device(
            self.user_id
        )
        if device_signed and master_signed:
            logger.info(f"{log_prefix}：{self._mask_device_id(self.device_id)}")
            return

        logger.warning(
            "自动签名设备未完全生效："
            f"device_signed={device_signed} master_signed={master_signed}"
        )

    async def _apply_key_backup_preference(self) -> None:
        """Resolve the Matrix v1.19 account-wide key-backup preference.

        An existing account preference enables backup on this headless client.
        An explicit local enablement is treated as the user's latest choice and
        is persisted for other clients. We deliberately do not write ``false``
        merely because the adapter's opt-in config uses its default value.
        """
        getter = getattr(self.client, "get_key_backup_preference", None)
        setter = getattr(self.client, "set_key_backup_preference", None)
        if not callable(getter):
            return

        try:
            preference = await getter()
        except Exception as e:
            logger.debug(f"读取 m.key_backup 偏好失败，沿用本地配置：{e}")
            return

        if preference is True and not self.enable_key_backup:
            self.enable_key_backup = True
            logger.info("已根据账户 m.key_backup 偏好启用密钥备份")
            return

        if self.enable_key_backup and preference is not True and callable(setter):
            try:
                await setter(True)
                logger.info("已同步账户 m.key_backup 偏好：enabled=true")
            except Exception as e:
                logger.warning(f"同步 m.key_backup 偏好失败：{e}")

    async def initialize(self):
        """初始化 E2EE 组件"""
        if not vodozemac_available():
            logger.warning("vodozemac 未安装，E2EE 功能不可用")
            return False

        try:
            # 创建存储和加密机器
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

            # 初始化 SAS 验证
            from ..verification import SASVerification

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

            # 初始化密钥备份和交叉签名
            from ...key_backup import KeyBackup
            from ...signing import CrossSigning

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

            # 自动签名自己的设备（使设备变为"已验证"状态）
            if self._cross_signing.has_master_key:
                await self._finalize_own_device_trust("已自动签名设备")
            else:
                # 如果没有交叉签名密钥，尝试上传
                try:
                    await self._cross_signing.upload_cross_signing_keys()
                    await self._finalize_own_device_trust(
                        "已上传交叉签名密钥并签名设备"
                    )
                except Exception as e:
                    logger.warning(f"上传交叉签名密钥失败（可能需要 UIA）：{e}")

            self._initialized = True
            logger.info(
                f"E2EE 初始化成功 (device_id: {self._mask_device_id(self.device_id)})"
            )

            # 初始化完成后，尝试为自己的未验证设备发起验证
            await self._verify_untrusted_own_devices()

            # 启动定期密钥分发检查任务
            if self.key_share_check_interval > 0:
                await self._start_key_share_check_task()
                logger.info(
                    f"已启动定期密钥分发检查任务，间隔：{self.key_share_check_interval} 秒"
                )
            else:
                logger.info(
                    "Room-key distribution is using lazy mode; keys will be "
                    "rechecked on encrypted sends and device-list changes"
                )

            return True

        except Exception as e:
            logger.error(f"E2EE 初始化失败：{e}")
            return False
