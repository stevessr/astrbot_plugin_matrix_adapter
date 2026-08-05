"""Reaction dispatch for the Matrix reaction tool."""

from astrbot.api import logger

from ....utils import MatrixUtils


async def _send_matrix_reaction(
    plugin,
    event,
    target_platform_id: str,
    target_room_id: str,
    target_event_id: str,
    reaction_raw: str,
):
    """Send the reaction; returns (reaction_key, reaction_event_id, error_or_None)."""
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
        return "", "", f"Failed to send Matrix reaction: {exc}"

    reaction_event_id = (
        str(response.get("event_id") or "").strip()
        if isinstance(response, dict)
        else ""
    )
    return reaction_key, reaction_event_id, None
