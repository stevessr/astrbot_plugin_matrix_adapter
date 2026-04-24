import asyncio
import json
import time
import uuid
from pathlib import Path

from astrbot.api import logger
from astrbot.api.platform import Platform, PlatformMetadata, register_platform_adapter

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
    DEFAULT_CONFIG,
    DEFAULT_MAX_UPLOAD_SIZE_BYTES,
    LOGO_PATH,
)
from .outbound_tracker import MatrixOutboundTracker
from .processors.event_handler import MatrixEventHandler
from .processors.event_processor import MatrixEventProcessor
from .receiver.receiver import MatrixReceiver
from .runtime_state import MatrixRuntimeState
from .sender.sender import MatrixSender

# Sticker 支持
from .sticker import StickerAvailabilityStore, StickerPackSyncer, StickerStorage
from .sync.sync_manager import MatrixSyncManager
from .utils.utils import MatrixUtils


def _cleanup_platform_registration(adapter_name: str = "matrix") -> None:
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


def _inject_astrbot_field_metadata() -> dict | None:
    """注入 Matrix 适配器的字段元数据到 AstrBot 配置系统

    将 config_metadata.json 中定义的字段描述注入到 CONFIG_METADATA_2 和 CONFIG_METADATA_3 中，
    以便 WebUI 能够显示 Matrix 适配器各配置项的说明。
    """
    try:
        metadata_path = Path(__file__).with_name("config_metadata.json")
        try:
            matrix_items = json.loads(metadata_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.debug(f"读取 Matrix 字段元数据失败：{e}")
            return
        if not isinstance(matrix_items, dict):
            logger.debug("Matrix 字段元数据格式错误，期望为 dict")
            return

        return matrix_items

    except Exception as e:
        logger.error(f"注入 AstrBot 字段元数据失败：{e}")
        return None


def _load_i18n_resources() -> dict[str, dict]:
    """加载 i18n 资源文件

    Returns:
        包含各语言 i18n 数据的字典
    """
    LANG = ["zh-CN", "en-US", "ru-RU"]
    i18n_data = {}
    try:
        for lang in LANG:
            path = Path(__file__).parent / "i18n" / f"{lang}.json"
            if path.exists():
                i18n_data[lang] = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.debug(f"加载 i18n 资源失败：{e}")

    return i18n_data


@register_platform_adapter(
    "matrix",
    "Matrix 协议适配器",
    default_config_tmpl=DEFAULT_CONFIG,
    adapter_display_name="Matrix",
    # NOTE: Matrix 通过 MSC4357 live messages 可以选择性支持流式输出
    support_streaming_message=True,
    logo_path=LOGO_PATH,
    i18n_resources=_load_i18n_resources(),
    config_metadata=_inject_astrbot_field_metadata(),
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
        platform_settings: dict,  # noqa: ARG002 - required by Platform interface
        event_queue: asyncio.Queue,
    ) -> None:
        webhook_uuid = str(platform_config.get("webhook_uuid") or "").strip()
        if not webhook_uuid:
            platform_config["webhook_uuid"] = uuid.uuid4().hex[:16]

        super().__init__(platform_config, event_queue)
        # Store MatrixConfig separately to maintain functionality
        self._matrix_config = MatrixConfig(platform_config)
        # 记录启动时间（毫秒）。用于过滤启动前的历史消息，避免启动时回复历史消息
        self._startup_ts = int(time.time() * 1000)

        # 使用自定义 HTTP 客户端（不依赖 matrix-nio）
        self.client = MatrixHTTPClient(homeserver=self._matrix_config.homeserver)
        self.runtime_state = MatrixRuntimeState()
        self.client.runtime_state = self.runtime_state

        # 使用新的存储路径逻辑
        from .storage_paths import MatrixStoragePaths

        # 确保 user_id 存在（在 _validate() 中已验证，但为类型检查器添加断言）
        if not self._matrix_config.user_id:
            raise ValueError("user_id is required for storage initialization")

        # 获取用户的存储目录
        user_storage_dir = MatrixStoragePaths.get_user_storage_dir(
            self._matrix_config.store_path,
            self._matrix_config.homeserver,
            self._matrix_config.user_id,
        )

        # 确保目录存在
        MatrixStoragePaths.ensure_directory(user_storage_dir, treat_as_file=False)

        self.storage_dir = str(user_storage_dir)
        self.outbound_tracker = MatrixOutboundTracker(
            user_storage_dir=user_storage_dir,
            store_path=self._matrix_config.store_path,
            backend=getattr(self._matrix_config, "storage_backend_config", None).backend
            if getattr(self._matrix_config, "storage_backend_config", None)
            else "json",
            pgsql_dsn=getattr(
                self._matrix_config, "storage_backend_config", None
            ).pgsql_dsn
            if getattr(self._matrix_config, "storage_backend_config", None)
            else "",
            pgsql_schema=getattr(
                self._matrix_config, "storage_backend_config", None
            ).pgsql_schema
            if getattr(self._matrix_config, "storage_backend_config", None)
            else "public",
            pgsql_table_prefix=getattr(
                self._matrix_config, "storage_backend_config", None
            ).pgsql_table_prefix
            if getattr(self._matrix_config, "storage_backend_config", None)
            else "matrix_store",
        )
        self.client.outbound_tracker = self.outbound_tracker

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
            on_token_invalid=self._sync_on_token_invalid,
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
                    logger.info("检测到已配置的恢复密钥")
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
                    proactive_key_exchange=self._matrix_config.e2ee_proactive_key_exchange,
                    key_maintenance_interval=self._matrix_config.e2ee_key_maintenance_interval,
                    otk_threshold_ratio=self._matrix_config.e2ee_otk_threshold_ratio,
                    key_share_check_interval=self._matrix_config.e2ee_key_share_check_interval,
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
        self.sync_manager.on_sync = self._on_sync_response
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

        # Sticker 存储（全局共享）与可用列表（按账户隔离）
        available_path = Path(self.storage_dir) / "sticker_available.json"
        self.sticker_available = StickerAvailabilityStore(available_path)
        self.sticker_storage = StickerStorage(availability_store=self.sticker_available)
        self.sticker_syncer = StickerPackSyncer(
            storage=self.sticker_storage,
            client=self.client,
            availability_store=self.sticker_available,
        )

        logger.info("Matrix Adapter 初始化完成")

    def meta(self) -> PlatformMetadata:
        id_ = str(self.config.get("id") or "matrix")
        return PlatformMetadata(
            name="matrix",
            description="Matrix 协议适配器",
            id=id_,
            adapter_display_name="Matrix",
            logo_path="matrix.svg",
            # NOTE: Matrix 通过 MSC4357 live messages 选择性支持流式消息
            support_streaming_message=True,
        )

    def unified_webhook(self) -> bool:
        webhook_uuid = str(self.config.get("webhook_uuid") or "").strip()
        return bool(
            webhook_uuid and self._matrix_config.auth_method in {"oauth2", "qr"}
        )

    def get_stats(self) -> dict:
        stat = super().get_stats()
        login_info = getattr(self.auth, "login_info", {})
        stat["matrix"] = {
            "configured": bool(self._matrix_config.access_token),
            "user_id": self._matrix_config.user_id,
            "homeserver": self._matrix_config.homeserver,
            "qr_status": login_info.get("status"),
            "qrcode": login_info.get("qrcode"),
            "qrcode_img_content": login_info.get("qrcode_img_content"),
            "qr_error": login_info.get("error"),
        }
        return stat

    async def _persist_auth_config_if_needed(self) -> None:
        access_token = str(getattr(self.auth, "access_token", "") or "")
        refresh_token = str(getattr(self.auth, "refresh_token", "") or "")
        if access_token:
            self._matrix_config.access_token = access_token
        if refresh_token:
            self._matrix_config.refresh_token = refresh_token
        needs_save = bool(getattr(self.auth, "_config_needs_save", False))
        persisted = True
        if access_token or refresh_token or needs_save:
            persisted = await self._save_config()
        if hasattr(self.auth, "_config_needs_save") and persisted:
            self.auth._config_needs_save = False

    async def _sync_on_token_invalid(self) -> bool:
        refreshed = await self.auth.refresh_session()
        if refreshed:
            await self._persist_auth_config_if_needed()
        return refreshed

    async def _save_config(self) -> bool:
        """Save configuration changes back to the current platform config."""
        try:
            changed_fields: list[str] = []
            config_updates = {
                "matrix_access_token": str(
                    self._matrix_config.access_token or ""
                ).strip(),
                "matrix_refresh_token": str(
                    getattr(self._matrix_config, "refresh_token", "") or ""
                ).strip(),
                "matrix_user_id": str(self._matrix_config.user_id or "").strip(),
                "webhook_uuid": str(self.config.get("webhook_uuid") or "").strip(),
            }

            for field, value in config_updates.items():
                if value and self.config.get(field) != value:
                    self.config[field] = value
                    changed_fields.append(field)

            if not changed_fields:
                logger.debug("Matrix 配置无变化，跳过保存")
                return True

            config_owner = getattr(self, "config_owner", None)
            if config_owner is None:
                try:
                    from astrbot.core import astrbot_config as global_astrbot_config

                    platform_id = str(self.config.get("id") or "")
                    platform_type = str(self.config.get("type") or "matrix")
                    for platform in global_astrbot_config.get("platform", []):
                        if not isinstance(platform, dict):
                            continue
                        if platform is self.config or (
                            str(platform.get("id") or "") == platform_id
                            and str(platform.get("type") or "") == platform_type
                        ):
                            self.config = platform
                            config_owner = global_astrbot_config
                            break
                except Exception as e:
                    logger.debug(f"定位全局 Matrix 配置失败：{e}")

            if config_owner is None:
                logger.warning("保存 Matrix 配置失败：未找到可用的配置所有者")
                return False

            config_owner.save_config()
            logger.info(f"Matrix 适配器配置已更新：{', '.join(changed_fields)}")
            return True
        except Exception as e:
            logger.warning(f"保存 Matrix 配置失败：{e}")
            return False

    def get_client(self) -> MatrixHTTPClient:
        return self.client

    async def webhook_callback(self, request):
        return await self.auth.handle_webhook_callback(request)
