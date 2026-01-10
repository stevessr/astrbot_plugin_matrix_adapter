import asyncio
import time

from astrbot.api import logger
from astrbot.api.platform import Platform, PlatformMetadata, register_platform_adapter
from astrbot.core.config.astrbot_config import AstrBotConfig

from .adapter_message import MatrixAdapterMessageMixin
from .adapter_runtime import MatrixAdapterRuntimeMixin
from .adapter_send import MatrixAdapterSendMixin
from .auth.auth import MatrixAuth

# 自定义 Matrix 客户端（不依赖 matrix-nio）
from .client import MatrixHTTPClient

# Import commands to register them
# 组件导入 - Updated to new structure
from .config import MatrixConfig
from .constants import (
    DEFAULT_MAX_UPLOAD_SIZE_BYTES,
)
from .processors.event_handler import MatrixEventHandler
from .processors.event_processor import MatrixEventProcessor
from .receiver.receiver import MatrixReceiver
from .sender.sender import MatrixSender

# Sticker 支持
from .sticker import StickerPackSyncer, StickerStorage
from .sync.sync_manager import MatrixSyncManager
from .utils.utils import MatrixUtils


def _cleanup_platform_registration(adapter_name: str = "matrix"):
    """清理之前的平台适配器注册（用于热重载）

    在模块重新加载时，需要清理之前注册的适配器，避免重复注册错误。
    """
    try:
        from astrbot.core.platform.register import platform_cls_map, platform_registry

        # 从 platform_cls_map 中移除
        if adapter_name in platform_cls_map:
            del platform_cls_map[adapter_name]
            logger.debug(f"已清理平台适配器 {adapter_name} 的类映射")

        # 从 platform_registry 中移除匹配的 PlatformMetadata
        to_remove = [pm for pm in platform_registry if pm.name == adapter_name]
        for pm in to_remove:
            platform_registry.remove(pm)
            logger.debug(f"已清理平台适配器 {adapter_name} 的注册元数据")

    except Exception as e:
        logger.debug(f"清理平台适配器注册时出错（可忽略）: {e}")


# 在模块加载时执行清理，避免热重载时的重复注册错误
_cleanup_platform_registration("matrix")


def _inject_astrbot_field_metadata():
    """注入 Matrix 适配器的字段元数据到 AstrBot 配置系统"""
    try:
        from astrbot.core.config.default import CONFIG_METADATA_2

        pg = CONFIG_METADATA_2.get("platform_group")
        if not isinstance(pg, dict):
            return
        metadata = pg.get("metadata")
        if not isinstance(metadata, dict):
            return
        platform = metadata.get("platform")
        if not isinstance(platform, dict):
            return
        items = platform.get("items")
        if not isinstance(items, dict):
            return

        matrix_items = {
            # 核心认证配置
            "matrix_homeserver": {
                "description": "Homeserver URL",
                "type": "string",
                "hint": "Matrix 服务器地址，例如 https://matrix.org",
                "obvious_hint": True,
            },
            "matrix_user_id": {
                "description": "用户 ID",
                "type": "string",
                "hint": "Matrix 用户 ID，格式：@username:homeserver.com",
                "obvious_hint": True,
            },
            "matrix_password": {
                "description": "密码",
                "type": "string",
                "hint": "Matrix 账户密码（密码认证模式必填）",
                "condition": {"matrix_auth_method": "password"},
            },
            "matrix_access_token": {
                "description": "Access Token",
                "type": "string",
                "hint": "Matrix Access Token（Token 认证模式必填）",
                "condition": {"matrix_auth_method": "token"},
            },
            "matrix_auth_method": {
                "description": "认证方式",
                "type": "string",
                "hint": "认证方式：password（密码）、token（Token）、oauth2（OAuth2）",
                "options": ["password", "token", "oauth2"],
            },
            "matrix_device_name": {
                "description": "设备名称",
                "type": "string",
                "hint": "设备显示名称，默认 AstrBot",
            },
            # 功能配置
            "matrix_auto_join_rooms": {
                "description": "自动加入房间",
                "type": "bool",
                "hint": "是否自动接受房间邀请，默认 True",
            },
            "matrix_sync_timeout": {
                "description": "同步超时",
                "type": "int",
                "hint": "同步超时时间（毫秒），默认 30000",
            },
            "matrix_enable_threading": {
                "description": "启用消息线程",
                "type": "bool",
                "hint": "是否使用消息线程（Threading）回复，默认 False",
            },
            "matrix_use_notice": {
                "description": "使用通知类型消息",
                "type": "bool",
                "hint": "启用后机器人将使用 m.notice 类型发送消息，而不是 m.text。m.notice 通常用于机器人消息，不会触发通知声音",
            },
            # E2EE 配置
            "matrix_enable_e2ee": {
                "description": "启用端到端加密",
                "type": "bool",
                "hint": "是否启用 E2EE 端到端加密（试验性），默认 False",
            },
            "matrix_e2ee_auto_verify": {
                "description": "自动验证模式",
                "type": "string",
                "hint": "自动验证模式：auto_accept / auto_reject / manual，默认 auto_accept",
                "options": ["auto_accept", "auto_reject", "manual"],
                "condition": {"matrix_enable_e2ee": True},
            },
            "matrix_e2ee_trust_on_first_use": {
                "description": "首次使用信任",
                "type": "bool",
                "hint": "是否自动信任首次使用的设备，默认 False",
                "condition": {"matrix_enable_e2ee": True},
            },
            "matrix_e2ee_key_backup": {
                "description": "启用密钥备份",
                "type": "bool",
                "hint": "是否启用密钥备份，默认 False",
                "condition": {"matrix_enable_e2ee": True},
            },
            "matrix_e2ee_recovery_key": {
                "description": "恢复密钥",
                "type": "string",
                "hint": "E2EE 恢复密钥（Base58 或 Base64 格式），留空则自动生成",
                "condition": {"matrix_enable_e2ee": True},
            },
        }

        # 仅在缺失时新增；若已存在则尽量补齐缺失的字段
        for k, v in matrix_items.items():
            if k not in items:
                items[k] = v
            else:
                it = items[k]
                if "description" not in it and "description" in v:
                    it["description"] = v["description"]
                if "type" not in it and "type" in v:
                    it["type"] = v["type"]
                if "hint" not in it and "hint" in v:
                    it["hint"] = v["hint"]
                if "obvious_hint" not in it and "obvious_hint" in v:
                    it["obvious_hint"] = v["obvious_hint"]

        logger.debug("已为 Matrix 适配器注入字段元数据")
    except Exception as e:
        try:
            logger.debug(f"注入 Matrix 字段元数据失败：{e}")
        except Exception:
            pass


@register_platform_adapter(
    "matrix",
    "Matrix 协议适配器",
    default_config_tmpl={
        # 核心配置
        "id": "default",
        "type": "matrix",
        "enable": False,
        "hint": "Matrix 协议适配器，支持端到端加密、OAuth2 认证、消息线程等功能。",
        # 认证配置
        "matrix_homeserver": "https://matrix.org",
        "matrix_user_id": "",
        "matrix_password": "",
        "matrix_access_token": "",
        "matrix_auth_method": "password",
        "matrix_device_name": "AstrBot",
        # 功能配置
        "matrix_auto_join_rooms": True,
        "matrix_sync_timeout": 30000,
        "matrix_enable_threading": False,
        "matrix_use_notice": False,
        # E2EE 配置
        "matrix_enable_e2ee": False,
        "matrix_e2ee_auto_verify": "auto_accept",
        "matrix_e2ee_trust_on_first_use": False,
        "matrix_e2ee_key_backup": False,
        "matrix_e2ee_recovery_key": "",
    },
    adapter_display_name="Matrix",
    support_streaming_message=True,
    logo_path="matrix.svg",
)
class MatrixPlatformAdapter(
    MatrixAdapterSendMixin,
    MatrixAdapterRuntimeMixin,
    MatrixAdapterMessageMixin,
    Platform,
):
    def __init__(
        self,
        platform_config: dict,
        platform_settings: dict,
        event_queue: asyncio.Queue,
    ) -> None:
        super().__init__(platform_config, event_queue)
        # Store MatrixConfig separately to maintain functionality
        self._matrix_config = MatrixConfig(platform_config)
        # 记录启动时间（毫秒）。用于过滤启动前的历史消息，避免启动时回复历史消息
        self._startup_ts = int(time.time() * 1000)
        # 消息历史管理器（稍后通过 Context 获取）
        self.message_history_manager = None

        # 使用自定义 HTTP 客户端（不依赖 matrix-nio）
        self.client = MatrixHTTPClient(homeserver=self._matrix_config.homeserver)

        # 使用新的存储路径逻辑
        from .storage_paths import MatrixStoragePaths

        # 获取用户的存储目录
        user_storage_dir = MatrixStoragePaths.get_user_storage_dir(
            self._matrix_config.store_path,
            self._matrix_config.homeserver,
            self._matrix_config.user_id,
        )

        # 确保目录存在
        MatrixStoragePaths.ensure_directory(user_storage_dir)

        self.storage_dir = str(user_storage_dir)

        # 初始化认证（不再需要指定 token_store_path，会自动生成）
        self.auth = MatrixAuth(
            self.client,
            self._matrix_config,
            token_store_path=None,  # 让 MatrixAuth 自动生成路径
        )

        self.sender = MatrixSender(self.client)

        # 获取机器人名称用于检测 @
        bot_name = platform_config.get(
            "matrix_bot_name", self._matrix_config.device_name
        )
        self.receiver = MatrixReceiver(
            self._matrix_config.user_id,
            lambda mxc: MatrixUtils.mxc_to_http(mxc, self._matrix_config.homeserver),
            bot_name=bot_name,
            client=self.client,  # 传递 client 用于下载图片
            matrix_config=self._matrix_config,  # 传递配置用于媒体设置
        )
        self.event_handler = MatrixEventHandler(
            self.client, self._matrix_config.auto_join_rooms
        )

        # Initialize sync manager with new storage path logic
        self.sync_manager = MatrixSyncManager(
            client=self.client,
            sync_timeout=self._matrix_config.sync_timeout,
            auto_join_rooms=self._matrix_config.auto_join_rooms,
            homeserver=self._matrix_config.homeserver,
            user_id=self._matrix_config.user_id,
            store_path=self._matrix_config.store_path,
            on_token_invalid=self.auth.refresh_session,
        )

        # Initialize event processor
        self.event_processor = MatrixEventProcessor(
            client=self.client,
            user_id=self._matrix_config.user_id,
            startup_ts=self._startup_ts,
        )

        # Initialize E2EE manager (if enabled)
        self.e2ee_manager = None
        if self._matrix_config.enable_e2ee:
            from .e2ee import VODOZEMAC_AVAILABLE, E2EEManager

            if VODOZEMAC_AVAILABLE:
                recovery_key = self._matrix_config.e2ee_recovery_key
                if recovery_key:
                    logger.info(
                        f"配置的恢复密钥：{recovery_key[:4]}...{recovery_key[-4:]}"
                    )
                else:
                    logger.warning("未配置恢复密钥 (matrix_e2ee_recovery_key)")

                self.e2ee_manager = E2EEManager(
                    client=self.client,
                    user_id=self._matrix_config.user_id,
                    device_id=self.client.device_id
                    or self._matrix_config.device_id,  # 优先使用服务器返回的 device_id
                    store_path=self._matrix_config.e2ee_store_path,
                    homeserver=self._matrix_config.homeserver,
                    auto_verify_mode=self._matrix_config.e2ee_auto_verify,
                    enable_key_backup=self._matrix_config.e2ee_key_backup,
                    recovery_key=recovery_key,
                    trust_on_first_use=self._matrix_config.e2ee_trust_on_first_use,
                    password=self._matrix_config.password,
                )
                # 传递给 event_processor 用于解密
                self.event_processor.e2ee_manager = self.e2ee_manager
                # 传递给 sender 用于加密发送
                self.sender.e2ee_manager = self.e2ee_manager
            else:
                logger.warning(
                    "E2EE 已启用但 vodozemac 未安装。请运行：pip install vodozemac"
                )

        # Set up callbacks
        self.sync_manager.set_room_event_callback(
            self.event_processor.process_room_events
        )
        self.sync_manager.set_to_device_event_callback(
            self.event_processor.process_to_device_events
        )
        self.sync_manager.set_invite_callback(
            self.event_handler.invite_callback
        )  # Fixed: using event_handler method
        self.sync_manager.set_leave_callback(self.event_processor.process_leave_events)
        self.sync_manager.set_ephemeral_callback(
            self.event_processor.process_ephemeral_events
        )
        self.sync_manager.set_room_account_data_callback(
            self.event_processor.process_room_account_data_events
        )
        self.sync_manager.set_account_data_callback(
            self.event_processor.process_account_data_events
        )
        self.sync_manager.set_presence_callback(
            self.event_processor.process_presence_events
        )
        self.sync_manager.set_device_lists_callback(
            self.event_processor.process_device_lists
        )
        self.sync_manager.set_device_one_time_keys_count_callback(
            self.event_processor.process_device_one_time_keys_count
        )
        self.event_processor.set_message_callback(self.message_callback)

        # 最大上传文件大小（将在 run 时从服务器获取）
        self.max_upload_size: int = DEFAULT_MAX_UPLOAD_SIZE_BYTES

        # Sticker 存储和同步器
        self.sticker_storage = StickerStorage()
        self.sticker_syncer = StickerPackSyncer(
            storage=self.sticker_storage,
            client=self.client,
        )

        # 将 sticker 同步器传递给事件处理器
        self.event_handler.set_sticker_syncer(
            self.sticker_syncer,
            auto_sync=self._matrix_config.sticker_auto_sync,
        )

        logger.info("Matrix Adapter 初始化完成")

    def meta(self) -> PlatformMetadata:
        id_ = getattr(self._matrix_config, "id", None) or "matrix"
        return PlatformMetadata(
            name="matrix",
            description="Matrix 协议适配器",
            id=id_,
            adapter_display_name="Matrix",
            logo_path="matrix.svg",
        )

    async def _handle_invite(self, room_id: str, invite_data: dict):
        """处理房间邀请"""
        # This wrapper can be removed since we use event_handler directly,
        # but sticking to existing logic, it seems I removed it and used event_handler.invite_callback directly above
        # Keeping it for now if needed, but it seems unused in my updated __init__
        try:
            logger.info(f"收到房间邀请到 {room_id}")
            result = await self.client.join_room(room_id)
            if result.get("room_id"):
                logger.info(f"成功加入房间 {room_id}")
            else:
                logger.error(f"加入房间失败 {room_id}: {result}")
        except Exception as e:
            logger.error(f"加入房间时出错 {room_id}: {e}")

    async def _save_config(self):
        """Save configuration changes back to the platform config"""
        try:
            # Import here to avoid circular dependency

            # Load the main config
            main_config = AstrBotConfig()

            # Find and update our platform config
            for platform in main_config.get("platform", []):
                if platform.get("id") == self._original_config.get("id"):
                    # device_id 现在由系统管理，不再保存到配置中
                    if self._matrix_config.access_token and not platform.get(
                        "matrix_access_token"
                    ):
                        platform["matrix_access_token"] = (
                            self._matrix_config.access_token
                        )
                        logger.info("已保存 access_token 到配置以供将来使用")
                    break

            # Save the updated config
            main_config.save_config()
            logger.debug("Matrix 适配器配置保存成功")
        except Exception as e:
            logger.warning(f"保存 Matrix 配置失败：{e}")

    def get_client(self):
        return self.client
