"""E2EE manager resolution for the manual approval command."""

from astrbot.api import logger

from ....utils import MatrixUtils


async def _resolve_e2ee_manager(plugin, event, matrix_platform_id: str):
    """Resolve the e2ee_manager; returns (manager, error_text_or_None)."""
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

    if e2ee_manager:
        return e2ee_manager, None

    current_platform_name = str(event.get_platform_name() or "").strip().lower()
    current_platform_id = str(event.get_platform_id() or "")
    requested_platform_id = str(matrix_platform_id or "").strip()

    target_platform_id = requested_platform_id
    if not target_platform_id and current_platform_name == "matrix":
        target_platform_id = current_platform_id

    if not target_platform_id and current_platform_name != "matrix":
        matrix_platform_ids = MatrixUtils.list_matrix_platform_ids(plugin.context)
        if not matrix_platform_ids:
            return None, "未检测到可用的 Matrix 适配器"
        if len(matrix_platform_ids) > 1:
            return None, (
                "检测到多个 Matrix 适配器，请在命令末尾指定 matrix_platform_id：\n"
                + "\n".join(f"- {platform_id}" for platform_id in matrix_platform_ids)
            )
        target_platform_id = matrix_platform_ids[0]

    e2ee_manager = MatrixUtils.get_matrix_e2ee_manager(
        plugin.context,
        target_platform_id,
        fallback_to_first=not bool(target_platform_id),
    )

    if not e2ee_manager:
        return None, "端到端加密未启用、不可用，或指定的 Matrix 适配器不存在"
    return e2ee_manager, None
