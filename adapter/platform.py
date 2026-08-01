import asyncio
import json
import time
import uuid
from pathlib import Path

from astrbot.api import logger
from astrbot.api.platform import Platform, PlatformMetadata, register_platform_adapter

from ..client import MatrixHTTPClient
from ..config.matrix import MatrixConfig
from ..constants import DEFAULT_CONFIG, LOGO_PATH
from .composition import build_adapter_services
from .message import MatrixAdapterMessageMixin
from .runtime import MatrixAdapterRuntimeMixin
from .send import MatrixAdapterSendMixin


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
        metadata_path = Path(__file__).resolve().parent.parent / "config_metadata.json"
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
            path = Path(__file__).resolve().parent.parent / "i18n" / f"{lang}.json"
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
    # Matrix 的独立 send_streaming 接口通过 MSC4357 实现流式输出。
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
        self._matrix_config = MatrixConfig(platform_config)
        self._startup_ts = int(time.time() * 1000)

        services = build_adapter_services(
            platform_config=platform_config,
            matrix_config=self._matrix_config,
            startup_ts=self._startup_ts,
            on_token_invalid=self._sync_on_token_invalid,
            on_sync_response=self._on_sync_response,
            message_callback=self.message_callback,
        )
        self.client = services.client
        self.runtime_state = services.runtime_state
        self.storage_dir = services.storage_dir
        self.outbound_tracker = services.outbound_tracker
        self.auth = services.auth
        self.sender = services.sender
        self.receiver = services.receiver
        self.event_handler = services.event_handler
        self.sync_manager = services.sync_manager
        self.event_processor = services.event_processor
        self.e2ee_manager = services.e2ee_manager
        self.sticker_available = services.sticker_available
        self.sticker_storage = services.sticker_storage
        self.sticker_syncer = services.sticker_syncer
        self.max_upload_size = services.max_upload_size

        logger.info("Matrix Adapter 初始化完成")

    def meta(self) -> PlatformMetadata:
        id_ = str(self.config.get("id") or "matrix")
        return PlatformMetadata(
            name="matrix",
            description="Matrix 协议适配器",
            id=id_,
            adapter_display_name="Matrix",
            logo_path="matrix.svg",
            # 流式调度进入 send_streaming 后使用 MSC4357。
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
