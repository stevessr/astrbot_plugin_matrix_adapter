"""Manual Matrix device approval command workflow."""

from astrbot.api import logger

from .key import _fetch_device_fingerprint
from .resolve import _resolve_e2ee_manager
from .store import _store_approved_device


async def approve_device(
    plugin,
    event,
    user_id: str,
    device_id: str,
    matrix_platform_id: str = "",
):
    """手动批准 Matrix 设备。"""
    e2ee_manager, resolve_error = await _resolve_e2ee_manager(
        plugin, event, matrix_platform_id
    )
    if resolve_error:
        yield event.plain_result(resolve_error)
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
        fingerprint, fingerprint_error = await _fetch_device_fingerprint(
            client, user_id, device_id
        )
        if fingerprint_error:
            yield event.plain_result(fingerprint_error)
            return

        # Add to trusted devices
        approve_result = await _store_approved_device(
            verification, device_store, user_id, device_id, fingerprint
        )

        # If there is an active SAS verification session, continue protocol flow
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
