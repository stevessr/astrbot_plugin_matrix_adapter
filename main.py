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
            from .config.plugin import get_plugin_config, init_plugin_config

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
            from .events.matrix import MatrixPlatformEvent
        except ImportError as e:
            logger.error(f"导入 Matrix Adapter 失败，请检查依赖是否安装：{e}")
            # 抛出异常，避免处于"已加载但不可用"的不一致状态
            raise

    @filter.llm_tool(name="matrix_react_to_event")
    async def matrix_react_to_event(
        self,
        event: AstrMessageEvent,
        message_content: str,
        reaction: str,
        time: str = "",
        matrix_platform_id: str = "",
        room_id: str = "",
    ) -> str:
        """React to the nearest Matrix message matching the given content.

        Prefer exact body matches, then substring matches. When ``time`` is omitted,
        the search anchors at the current tool-call time (or the inbound message
        timestamp when available).

        Args:
            message_content(string): Text used to locate the target Matrix message.
                Exact matches are preferred over substring matches.
            reaction(string): Unicode emoji, emoji/sticker shortcode (e.g. ``:smile:``
                or ``thinking``), or custom Matrix reaction key / ``mxc://`` URL.
            time(string): Optional anchor time. Accepts Unix seconds/ms or ISO-8601.
                Defaults to now / inbound message time.
            matrix_platform_id(string): AstrBot Matrix platform ID. Required only
                when the current event is not Matrix and multiple Matrix adapters run.
            room_id(string): Optional Matrix room ID. Defaults to the current Matrix
                room.

        Returns:
            A concise status message for the next LLM turn.
        """
        from .utils.reaction_helpers import (
            default_anchor_time_ms,
            find_room_event_for_reaction,
            parse_reaction_anchor_time_ms,
        )

        query = str(message_content or "").strip()
        reaction_raw = str(reaction or "").strip()
        if not query:
            return (
                "A non-empty message_content is required to locate the target message."
            )
        if not reaction_raw:
            return "A non-empty Matrix reaction key is required."

        current_platform_name = str(event.get_platform_name() or "").strip().lower()
        target_platform_id = str(matrix_platform_id or "").strip()
        target_room_id = str(room_id or "").strip()
        message_obj = getattr(event, "message_obj", None)

        if current_platform_name == "matrix":
            target_platform_id = (
                target_platform_id or str(event.get_platform_id() or "").strip()
            )
            target_room_id = (
                target_room_id
                or str(
                    getattr(message_obj, "session_id", None)
                    or event.get_group_id()
                    or event.get_session_id()
                    or ""
                ).strip()
            )

        if not target_room_id:
            return "A Matrix room_id is required outside a Matrix message."

        if not target_platform_id:
            matrix_platform_ids = MatrixUtils.list_matrix_platform_ids(self.context)
            if not matrix_platform_ids:
                return "No running Matrix adapter is available."
            if len(matrix_platform_ids) > 1:
                return (
                    "Multiple Matrix adapters are running; provide matrix_platform_id: "
                    + ", ".join(matrix_platform_ids)
                )
            target_platform_id = matrix_platform_ids[0]

        client = MatrixUtils.get_matrix_client(
            self.context,
            target_platform_id,
            fallback_to_first=False,
        )
        if client is None:
            return f"Matrix adapter {target_platform_id!r} is not available."

        anchor_time_ms = parse_reaction_anchor_time_ms(time)
        if anchor_time_ms is None:
            anchor_time_ms = default_anchor_time_ms(event)

        try:
            matched = await find_room_event_for_reaction(
                client,
                target_room_id,
                query,
                anchor_time_ms=anchor_time_ms,
            )
        except Exception as exc:
            logger.warning("Matrix reaction target lookup failed: %s", exc)
            return f"Failed to locate Matrix message for reaction: {exc}"

        if not matched:
            return (
                "No Matrix message matched "
                f"{query!r} near the requested time in {target_room_id}."
            )

        target_event_id = str(matched.get("event_id") or "").strip()
        if not target_event_id:
            return "Matched Matrix event is missing event_id."

        try:
            reaction_key = await MatrixUtils.resolve_reaction_key(
                reaction_raw,
                context=self.context,
                room_id=target_room_id,
                platform_id=target_platform_id,
                event=event,
            )
            response = await MatrixUtils.send_reaction(
                self.context,
                target_room_id,
                target_event_id,
                reaction_key,
                platform_id=target_platform_id,
                fallback_to_first=False,
                resolve_key=False,
                event=event,
            )
        except Exception as exc:
            logger.warning("Matrix reaction tool failed: %s", exc)
            return f"Failed to send Matrix reaction: {exc}"

        reaction_event_id = (
            str(response.get("event_id") or "").strip()
            if isinstance(response, dict)
            else ""
        )
        matched_body = ""
        content = matched.get("content")
        if isinstance(content, dict):
            matched_body = str(content.get("body") or "").strip()
        result = (
            f"Sent Matrix reaction {reaction_key!r} to {target_event_id}"
            f" matching {query!r}"
        )
        if matched_body and matched_body != query:
            result += f" (body={matched_body!r})"
        result += "."
        if reaction_event_id:
            result += f" Reaction event: {reaction_event_id}."
        return result

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
                        + "\n".join(
                            f"- {platform_id}" for platform_id in matrix_platform_ids
                        )
                    )
                    return
                target_platform_id = matrix_platform_ids[0]

            e2ee_manager = MatrixUtils.get_matrix_e2ee_manager(
                self.context,
                target_platform_id,
                fallback_to_first=not bool(target_platform_id),
            )

        if not e2ee_manager:
            yield event.plain_result(
                "端到端加密未启用、不可用，或指定的 Matrix 适配器不存在"
            )
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
