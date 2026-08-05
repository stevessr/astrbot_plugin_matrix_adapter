"""Target platform, room, and client resolution for the Matrix reaction tool."""

from ....utils import MatrixUtils


def _resolve_reaction_context(plugin, event, matrix_platform_id: str, room_id: str):
    """Resolve target ids and client; returns (platform_id, room_id, client_or_error)."""
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
        return "", "", "A Matrix room_id is required outside a Matrix message."

    if not target_platform_id:
        matrix_platform_ids = MatrixUtils.list_matrix_platform_ids(plugin.context)
        if not matrix_platform_ids:
            return "", "", "No running Matrix adapter is available."
        if len(matrix_platform_ids) > 1:
            return (
                "",
                "",
                "Multiple Matrix adapters are running; provide matrix_platform_id: "
                + ", ".join(matrix_platform_ids),
            )
        target_platform_id = matrix_platform_ids[0]

    client = MatrixUtils.get_matrix_client(
        plugin.context,
        target_platform_id,
        fallback_to_first=False,
    )
    if client is None:
        return (
            target_platform_id,
            target_room_id,
            f"Matrix adapter {target_platform_id!r} is not available.",
        )
    return target_platform_id, target_room_id, client
