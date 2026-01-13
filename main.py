from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register

from .constants import PREFIX_ED25519


@register(
    "astrbot_plugin_matrix_adapter",
    "stevessr",
    "Matrix 协议适配器，支持端到端加密、消息线程等功能",
    "0.2.7",
)
class MatrixPlugin(Star):
    def __init__(self, context: Context, config=None):
        super().__init__(context, config)

        # 初始化插件级别配置（目录路径等）
        try:
            from .plugin_config import init_plugin_config

            # 使用传入的 config 参数（AstrBot 从 astrbot_plugin_matrix_adapter_config.json 加载）
            plugin_config = config if isinstance(config, dict) else {}
            init_plugin_config(plugin_config)
            logger.debug(
                f"Matrix 插件配置已加载：force_private_message={plugin_config.get('matrix_force_private_message', False)}"
            )
        except Exception as e:
            logger.error(
                f"Matrix 插件配置初始化失败，将使用默认配置：{e}",
                extra={"plugin_tag": "matrix", "short_levelname": "ERROR"},
            )

        try:
            from .matrix_adapter import _inject_astrbot_field_metadata

            _inject_astrbot_field_metadata()
            from .matrix_adapter import MatrixPlatformAdapter  # noqa
            from .matrix_event import MatrixPlatformEvent  # noqa
        except ImportError as e:
            logger.error(f"导入 Matrix Adapter 失败，请检查依赖是否安装：{e}")
            # 抛出异常，避免处于"已加载但不可用"的不一致状态
            raise

    # ========== Commands ==========
    # 装饰器必须定义在 main.py 中，否则 handler 的 __module__ 不匹配

    @filter.command("approve_device")
    async def approve_device(
        self, event: AstrMessageEvent, user_id: str, device_id: str
    ):
        """手动批准 Matrix 设备

        用法：/approve_device <用户 ID> <设备 ID>

        示例：
            /approve_device @user:example.com DEVICEID123
        """
        # Check if this is a Matrix event
        if event.platform_meta.name != "matrix":
            yield event.plain_result("此命令仅在 Matrix 平台可用")
            return

        # Access E2EE Manager from the adapter
        e2ee_manager = None
        try:
            # Try to get e2ee_manager from the message_obj's raw adapter
            message_obj = getattr(event, "message_obj", None)
            if message_obj:
                raw_message = getattr(message_obj, "raw_message", None)
                if raw_message:
                    # The adapter stores e2ee_manager
                    adapter = getattr(raw_message, "_adapter", None)
                    if adapter:
                        e2ee_manager = getattr(adapter, "e2ee_manager", None)
        except Exception as e:
            logger.debug(f"获取 e2ee_manager 失败：{e}")

        if not e2ee_manager:
            yield event.plain_result("端到端加密未启用或不可用")
            return

        if not e2ee_manager._verification:
            yield event.plain_result("验证模块未初始化")
            return

        try:
            # Query device keys to get the fingerprint
            client = e2ee_manager._client
            response = await client.query_keys({user_id: []})

            devices = response.get("device_keys", {}).get(user_id, {})
            if not devices:
                yield event.plain_result(f"未找到用户 {user_id} 的设备")
                return

            device_info = devices.get(device_id, {})
            if not device_info:
                yield event.plain_result(f"未找到用户 {user_id} 的设备 {device_id}")
                return

            keys = device_info.get("keys", {})
            fingerprint = keys.get(f"{PREFIX_ED25519}{device_id}")

            if not fingerprint:
                yield event.plain_result(
                    f"无法获取设备 {device_id} 的 Ed25519 密钥（指纹）"
                )
                return

            # Add to trusted devices
            e2ee_manager._verification.device_store.add_device(
                user_id, device_id, fingerprint
            )

            yield event.plain_result(
                f"✅ 设备已批准:\n"
                f"用户：{user_id}\n"
                f"设备：{device_id}\n"
                f"指纹：{fingerprint}"
            )
            logger.info(f"通过命令手动批准设备 {user_id}|{device_id}")

        except Exception as e:
            logger.error(f"批准设备失败：{e}")
            yield event.plain_result(f"❌ 批准设备失败：{e}")
