"""LLM-facing Matrix reaction workflow."""

from astrbot.api import logger

from ...utils import MatrixUtils


async def matrix_react_to_event(
    plugin,
    event,
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
    """
    from ...utils.reaction_helpers import (
        default_anchor_time_ms,
        find_room_event_for_reaction,
        parse_reaction_anchor_time_ms,
    )

    query = str(message_content or "").strip()
    reaction_raw = str(reaction or "").strip()
    if not query:
        return "A non-empty message_content is required to locate the target message."
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
        matrix_platform_ids = MatrixUtils.list_matrix_platform_ids(plugin.context)
        if not matrix_platform_ids:
            return "No running Matrix adapter is available."
        if len(matrix_platform_ids) > 1:
            return (
                "Multiple Matrix adapters are running; provide matrix_platform_id: "
                + ", ".join(matrix_platform_ids)
            )
        target_platform_id = matrix_platform_ids[0]

    client = MatrixUtils.get_matrix_client(
        plugin.context,
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
            context=plugin.context,
            room_id=target_room_id,
            platform_id=target_platform_id,
            event=event,
        )
        response = await MatrixUtils.send_reaction(
            plugin.context,
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
        f"Sent Matrix reaction {reaction_key!r} to {target_event_id} matching {query!r}"
    )
    if matched_body and matched_body != query:
        result += f" (body={matched_body!r})"
    result += "."
    if reaction_event_id:
        result += f" Reaction event: {reaction_event_id}."
    return result


__all__ = ["matrix_react_to_event"]
