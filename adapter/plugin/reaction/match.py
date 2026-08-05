"""Target message lookup for the Matrix reaction tool."""

from astrbot.api import logger


async def _find_reaction_target(
    client,
    target_room_id: str,
    query: str,
    time: str,
    event,
    parse_reaction_anchor_time_ms,
    default_anchor_time_ms,
    find_room_event_for_reaction,
):
    """Locate the nearest matching room event; returns (matched_or_None, error_or_None)."""
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
        return None, f"Failed to locate Matrix message for reaction: {exc}"
    return matched, None
