"""
E2EE Manager - 端到端加密管理器

整合 OlmMachine 和 HTTP 客户端，提供高层 E2EE 操作接口。
"""

import asyncio
from pathlib import Path
from typing import Literal

from astrbot.api import logger

from ..storage_backend import StorageBackendConfig, build_folder_namespace
from ..storage_paths import MatrixStoragePaths
from .crypto_store import CryptoStore
from .e2ee_manager_decrypt import E2EEManagerDecryptMixin
from .e2ee_manager_keys import E2EEManagerKeysMixin
from .e2ee_manager_requests import E2EEManagerRequestsMixin
from .e2ee_manager_secrets import E2EEManagerSecretsMixin
from .e2ee_manager_sessions import E2EEManagerSessionsMixin
from .e2ee_manager_verification import E2EEManagerVerificationMixin
from .olm_machine import VODOZEMAC_AVAILABLE, OlmMachine


class E2EEManager(
    E2EEManagerVerificationMixin,
    E2EEManagerKeysMixin,
    E2EEManagerDecryptMixin,
    E2EEManagerRequestsMixin,
    E2EEManagerSecretsMixin,
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
        proactive_key_exchange: bool = False,
        key_maintenance_interval: int = 60,
        otk_threshold_ratio: int = 33,
        key_share_check_interval: int = 0,
        *,
        storage_backend_config: StorageBackendConfig,
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
            key_share_check_interval: 定期主动检查并分发房间密钥的间隔（秒），0 表示禁用
            storage_backend_config: 运行时固定存储后端配置
        """
        self.client = client
        self.user_id = user_id
        self.device_id = device_id
        self.homeserver = homeserver
        self.password = password

        # 使用 MatrixStoragePaths 生成用户存储目录
        self._store_base_path = Path(store_path)
        self.store_path = MatrixStoragePaths.get_user_storage_dir(
            str(self._store_base_path), homeserver, user_id
        )
        self._store_namespace = build_folder_namespace(
            self.store_path, self._store_base_path
        )

        # Ensure the directory exists
        MatrixStoragePaths.ensure_directory(self.store_path)
        self.auto_verify_mode = auto_verify_mode
        self.enable_key_backup = enable_key_backup
        self.recovery_key = recovery_key
        self.trust_on_first_use = trust_on_first_use

        # 密钥交换积极性配置
        self.proactive_key_exchange = proactive_key_exchange
        self.key_maintenance_interval = key_maintenance_interval
        self.otk_threshold_ratio = max(1, min(100, otk_threshold_ratio))
        self.key_share_check_interval = key_share_check_interval
        self.storage_backend_config = storage_backend_config
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
        # session_id -> {"@user:server|DEVICEID", ...}
        self._room_key_share_cache: dict[str, set[str]] = {}
        # room_id -> (members, monotonic timestamp)
        self._room_members_cache: dict[str, tuple[list[str], float]] = {}
        self._room_members_cache_ttl_sec = 30.0
        # throttle one-time key maintenance to avoid frequent uploads
        self._last_otk_maintenance_ts = 0.0
        # 定期密钥分发检查的任务和锁
        self._key_share_check_task: asyncio.Task | None = None
        self._key_share_check_lock = asyncio.Lock()

    @property
    def is_available(self) -> bool:
        """检查 E2EE 是否可用"""
        return VODOZEMAC_AVAILABLE

    async def _start_key_share_check_task(self):
        """
        启动定期密钥分发检查任务
        """
        if self._key_share_check_task and not self._key_share_check_task.done():
            return

        async def _check_loop():
            while self._initialized:
                try:
                    await asyncio.sleep(self.key_share_check_interval)
                    if not self._initialized:
                        break
                    await self._proactive_check_key_sharing()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.warning(f"定期密钥分发检查失败：{e}")

        self._key_share_check_task = asyncio.create_task(_check_loop())

    def stop_key_share_check_task(self):
        """停止定期密钥分发检查任务"""
        if self._key_share_check_task and not self._key_share_check_task.done():
            self._key_share_check_task.cancel()
            self._key_share_check_task = None
            logger.debug("已停止定期密钥分发检查任务")

    async def _proactive_check_key_sharing(self):
        """主动检查并分发房间密钥"""
        if not self._olm or not self._initialized:
            return

        async with self._key_share_check_lock:
            try:
                room_ids = self._olm.get_megolm_outbound_room_ids()
                if not room_ids:
                    return

                affected_rooms = 0
                affected_devices = 0

                for room_id in room_ids:
                    members = await self._get_room_members(room_id)
                    if not members:
                        continue

                    session_info = self._olm.get_megolm_outbound_session_info(room_id)
                    if not session_info:
                        continue

                    session_id, session_key = session_info

                    # 检查缓存中已分享的设备数量
                    shared_devices = self._room_key_share_cache.get(session_id, set())

                    # 查询目标成员的设备密钥
                    device_keys_query = {user_id: [] for user_id in members}
                    response = await self.client.query_keys(device_keys_query)
                    device_keys = response.get("device_keys", {})

                    # 统计需要分发密钥的设备
                    devices_to_send = []
                    for user_id, user_devices in device_keys.items():
                        for device_id, device_info in user_devices.items():
                            keys = device_info.get("keys", {})
                            curve_key = keys.get(f"ed25519:{device_id}") or keys.get(
                                f"curve25519:{device_id}"
                            )
                            if not curve_key:
                                continue

                            cache_key = self._device_cache_key(
                                user_id, device_id, curve_key
                            )
                            if cache_key not in shared_devices:
                                devices_to_send.append(
                                    (user_id, device_id, curve_key, device_info)
                                )

                    if devices_to_send:
                        await self.ensure_room_keys_sent(
                            room_id=room_id,
                            members=members,
                            session_id=session_id,
                            session_key=session_key,
                            reason="proactive_check",
                        )
                        affected_rooms += 1
                        affected_devices += len(devices_to_send)

                if affected_rooms > 0:
                    logger.info(
                        f"主动密钥分发检查完成：rooms={affected_rooms} devices={affected_devices}"
                    )

            except Exception as e:
                logger.warning(f"主动密钥分发检查失败：{e}")

    async def initialize(self):
        """初始化 E2EE 组件"""
        if not VODOZEMAC_AVAILABLE:
            logger.warning("vodozemac 未安装，E2EE 功能不可用")
            return False

        try:
            # 创建存储和加密机器
            self._store = CryptoStore(
                self.store_path,
                self.user_id,
                self.device_id,
                storage_backend_config=self.storage_backend_config,
                namespace_key=self._store_namespace,
            )
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
                storage_backend_config=self.storage_backend_config,
                namespace_key=self._store_namespace,
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
                self.client,
                self.user_id,
                self.device_id,
                self._olm,
                self.password,
                storage_backend_config=self.storage_backend_config,
                namespace_key=self._store_namespace,
            )

            await self._key_backup.initialize()
            await self._cross_signing.initialize()

            # 如果启用密钥备份，创建或使用现有备份
            if self.enable_key_backup:
                if not self._key_backup._backup_version:
                    await self._key_backup.create_backup()

            # 仅当当前账户本地缺少房间密钥时才尝试恢复
            if self._key_backup.should_restore_for_session():
                logger.info("检测到本地房间密钥缺失，尝试从服务器备份恢复...")
                await self._key_backup.restore_room_keys_if_needed(reason="startup")

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

            # 启动定期密钥分发检查任务
            if self.key_share_check_interval > 0:
                await self._start_key_share_check_task()
                logger.info(
                    f"已启动定期密钥分发检查任务，间隔：{self.key_share_check_interval} 秒"
                )

            return True

        except Exception as e:
            logger.error(f"E2EE 初始化失败：{e}")
            return False
