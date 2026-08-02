"""Manual Matrix device approval command workflow."""

from astrbot.api import logger

from ...constants import PREFIX_ED25519
from ...utils import MatrixUtils


async def approve_device(
    plugin,
    event,
    user_id: str,
    device_id: str,
    matrix_platform_id: str = "",
):
    """手动批准 Matrix 设备。"""
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
            matrix_platform_ids = MatrixUtils.list_matrix_platform_ids(plugin.context)
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
            plugin.context,
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


__all__ = ["approve_device"]
