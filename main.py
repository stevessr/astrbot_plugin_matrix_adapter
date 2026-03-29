if __package__ in (None, ""):
    import sys
    from pathlib import Path

    package_root = Path(__file__).resolve().parent
    sys.path.insert(0, str(package_root.parent))
    __package__ = package_root.name

import bleach  # noqa: F401
import markdown_it  # noqa: F401

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register
from astrbot.core.star.filter.permission import PermissionType

from .constants import PREFIX_ED25519
from .utils import MatrixUtils


@register(
    "astrbot_plugin_matrix_adapter",
    "stevessr",
    "Matrix 协议适配器，支持端到端加密、消息线程等功能",
    "0.3.1",
)
class MatrixPlugin(Star):
    def __init__(self, context: Context, config=None):
        super().__init__(context, config)

        # 初始化插件级别配置（目录路径等）
        try:
            from .plugin_config import get_plugin_config, init_plugin_config

            # 使用传入的 config 参数（AstrBot 从 astrbot_plugin_matrix_adapter_config.json 加载）
            plugin_config = config if isinstance(config, dict) else {}
            init_plugin_config(plugin_config)
            plugin_cfg = get_plugin_config()
            logger.debug(
                "Matrix 插件配置已加载：force_message_type="
                f"{plugin_cfg.force_message_type}"
            )
        except Exception as e:
            logger.error(
                f"Matrix 插件配置初始化失败，将使用默认配置：{e}",
                extra={"plugin_tag": "matrix", "short_levelname": "ERROR"},
            )

        # 在导入 MatrixPlatformAdapter 之前注入字段元数据
        # 这样 @register_platform_adapter 装饰器执行时就能获取到正确的元数据
        try:
            from .matrix_adapter import _inject_astrbot_field_metadata

            _inject_astrbot_field_metadata()
            logger.debug("✅ Matrix 字段元数据已注入")
        except Exception as e:
            logger.error(f"❌ 注入 Matrix 字段元数据失败：{e}")

        try:
            from .matrix_adapter import MatrixPlatformAdapter  # noqa
            from .matrix_event import MatrixPlatformEvent  # noqa
        except ImportError as e:
            logger.error(f"导入 Matrix Adapter 失败，请检查依赖是否安装：{e}")
            # 抛出异常，避免处于"已加载但不可用"的不一致状态
            raise

    # ========== Commands ==========
    # 装饰器必须定义在 main.py 中，否则 handler 的 __module__ 不匹配

    @filter.command("approve_device")
    @filter.permission_type(PermissionType.ADMIN)
    async def approve_device(
        self,
        event: AstrMessageEvent,
        user_id: str,
        device_id: str,
        matrix_platform_id: str = "",
    ):
        """手动批准 Matrix 设备

        用法：
            /approve_device <用户 ID> <设备 ID> [matrix_platform_id]

        示例：
            /approve_device @user:example.com DEVICEID123
            /approve_device @user:example.com DEVICEID123 matrix-main
        """
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
            current_platform_name = str(event.get_platform_name() or "").strip().lower()
            current_platform_id = str(event.get_platform_id() or "")
            requested_platform_id = str(matrix_platform_id or "").strip()

            target_platform_id = requested_platform_id
            if not target_platform_id and current_platform_name == "matrix":
                target_platform_id = current_platform_id

            if not target_platform_id and current_platform_name != "matrix":
                matrix_platform_ids = MatrixUtils.list_matrix_platform_ids(self.context)
                if not matrix_platform_ids:
                    yield event.plain_result("未检测到可用的 Matrix 适配器")
                    return
                if len(matrix_platform_ids) > 1:
                    yield event.plain_result(
                        "检测到多个 Matrix 适配器，请在命令末尾指定 matrix_platform_id：\n"
                        + "\n".join(f"- {platform_id}" for platform_id in matrix_platform_ids)
                    )
                    return
                target_platform_id = matrix_platform_ids[0]

            e2ee_manager = MatrixUtils.get_matrix_e2ee_manager(
                self.context,
                target_platform_id,
                fallback_to_first=not bool(target_platform_id),
            )

        if not e2ee_manager:
            yield event.plain_result("端到端加密未启用、不可用，或指定的 Matrix 适配器不存在")
            return

        verification = getattr(e2ee_manager, "_verification", None)
        if not verification:
            yield event.plain_result("验证模块未初始化")
            return

        device_store = getattr(verification, "device_store", None)
        if not device_store:
            yield event.plain_result("验证设备存储未初始化")
            return

        try:
            # Query device keys to get the fingerprint
            client = e2ee_manager.client
            response = await client.query_keys({user_id: []})

            devices = (response.get("device_keys") or {}).get(user_id) or {}
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
            device_store.add_device(user_id, device_id, fingerprint)

            # If there is an active SAS verification session, continue protocol flow
            approve_result = None
            approve_method = getattr(verification, "approve_device", None)
            if callable(approve_method):
                try:
                    approve_result = await approve_method(device_id)
                except Exception as approve_error:
                    logger.warning(f"触发验证会话确认失败：{approve_error}")

            if (
                isinstance(approve_result, tuple)
                and len(approve_result) == 2
                and isinstance(approve_result[0], bool)
            ):
                session_ok, session_msg = approve_result
                if session_ok:
                    result_text = (
                        f"✅ 设备已批准并已发送验证确认:\n"
                        f"用户：{user_id}\n"
                        f"设备：{device_id}\n"
                        f"指纹：{fingerprint}\n"
                        f"会话：{session_msg}"
                    )
                else:
                    result_text = (
                        f"✅ 设备已批准:\n"
                        f"用户：{user_id}\n"
                        f"设备：{device_id}\n"
                        f"指纹：{fingerprint}\n"
                        f"会话：{session_msg}"
                    )
            else:
                result_text = (
                    f"✅ 设备已批准:\n"
                    f"用户：{user_id}\n"
                    f"设备：{device_id}\n"
                    f"指纹：{fingerprint}"
                )

            yield event.plain_result(result_text)
            logger.info(f"通过命令手动批准设备 {user_id}|{device_id}")

        except Exception as e:
            logger.error(f"批准设备失败：{e}")
            yield event.plain_result(f"❌ 批准设备失败：{e}")

    @filter.command("scan_device_qr")
    @filter.permission_type(PermissionType.ADMIN)
    async def scan_device_qr(
        self,
        event: AstrMessageEvent,
        user_id: str,
        device_id: str,
        qr_input: str,
        matrix_platform_id: str = "",
    ):
        """扫描 Matrix 设备验证二维码。

        用法：
            /scan_device_qr <用户 ID> <设备 ID> <二维码图片路径或 base64 载荷> [matrix_platform_id]
        """
        e2ee_manager = None
        try:
            message_obj = getattr(event, "message_obj", None)
            if message_obj:
                raw_message = getattr(message_obj, "raw_message", None)
                if raw_message:
                    adapter = getattr(raw_message, "_adapter", None)
                    if adapter:
                        e2ee_manager = getattr(adapter, "e2ee_manager", None)
        except Exception as e:
            logger.debug(f"获取 e2ee_manager 失败：{e}")

        if not e2ee_manager:
            current_platform_name = str(event.get_platform_name() or "").strip().lower()
            current_platform_id = str(event.get_platform_id() or "")
            requested_platform_id = str(matrix_platform_id or "").strip()

            target_platform_id = requested_platform_id
            if not target_platform_id and current_platform_name == "matrix":
                target_platform_id = current_platform_id

            if not target_platform_id and current_platform_name != "matrix":
                matrix_platform_ids = MatrixUtils.list_matrix_platform_ids(self.context)
                if not matrix_platform_ids:
                    yield event.plain_result("未检测到可用的 Matrix 适配器")
                    return
                if len(matrix_platform_ids) > 1:
                    yield event.plain_result(
                        "检测到多个 Matrix 适配器，请在命令末尾指定 matrix_platform_id：\n"
                        + "\n".join(f"- {platform_id}" for platform_id in matrix_platform_ids)
                    )
                    return
                target_platform_id = matrix_platform_ids[0]

            e2ee_manager = MatrixUtils.get_matrix_e2ee_manager(
                self.context,
                target_platform_id,
                fallback_to_first=not bool(target_platform_id),
            )

        if not e2ee_manager:
            yield event.plain_result("端到端加密未启用、不可用，或指定的 Matrix 适配器不存在")
            return

        verification = getattr(e2ee_manager, "_verification", None)
        if not verification:
            yield event.plain_result("验证模块未初始化")
            return

        scan_method = getattr(verification, "scan_qr", None)
        if not callable(scan_method):
            yield event.plain_result("当前验证模块不支持扫码验证")
            return

        try:
            ok, message = await scan_method(user_id, device_id, qr_input)
            prefix = "✅" if ok else "❌"
            yield event.plain_result(f"{prefix} {message}")
        except Exception as e:
            logger.error(f"扫码验证失败：{e}")
            yield event.plain_result(f"❌ 扫码验证失败：{e}")
