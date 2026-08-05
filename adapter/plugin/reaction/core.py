"""LLM-facing Matrix reaction workflow."""

from .match import _find_reaction_target
from .resolve import _resolve_reaction_context
from .send import _send_matrix_reaction


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
    from ....utils.reaction_helpers import (
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

    target_platform_id, target_room_id, resolved = _resolve_reaction_context(
        plugin, event, matrix_platform_id, room_id
    )
    if not isinstance(resolved, str):
        client = resolved
    else:
        return resolved

    matched, error = await _find_reaction_target(
        client,
        target_room_id,
        query,
        time,
        event,
        parse_reaction_anchor_time_ms,
        default_anchor_time_ms,
        find_room_event_for_reaction,
    )
    if error:
        return error

    if not matched:
        return (
            "No Matrix message matched "
            f"{query!r} near the requested time in {target_room_id}."
        )

    target_event_id = str(matched.get("event_id") or "").strip()
    if not target_event_id:
        return "Matched Matrix event is missing event_id."

    reaction_key, reaction_event_id, error = await _send_matrix_reaction(
        plugin,
        event,
        target_platform_id,
        target_room_id,
        target_event_id,
        reaction_raw,
    )
    if error:
        return error

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
