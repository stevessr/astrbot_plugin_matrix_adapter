"""Room history collection and reaction target lookup."""

from __future__ import annotations

from typing import Any

from astrbot.api import logger

from ..keys import _maybe_await
from .matching import select_nearest_matching_event


async def collect_room_message_events(
    client: Any,
    room_id: str,
    *,
    limit: int = 100,
    max_pages: int = 3,
) -> list[dict[str, Any]]:
    """Fetch recent room events newest-first for reaction targeting."""
    if client is None:
        return []
    room_messages = getattr(client, "room_messages", None)
    if not callable(room_messages):
        return []

    collected: list[dict[str, Any]] = []
    from_token: str | None = None
    pages = max(1, int(max_pages))
    page_limit = max(1, min(int(limit), 100))

    for _ in range(pages):
        try:
            raw_response = room_messages(
                room_id=room_id,
                from_token=from_token,
                direction="b",
                limit=page_limit,
            )
            response = await _maybe_await(raw_response)
        except TypeError:
            try:
                raw_response = room_messages(
                    room_id,
                    from_token,
                    None,
                    "b",
                    page_limit,
                )
                response = await _maybe_await(raw_response)
            except Exception as exc:
                logger.debug(
                    "Failed to load Matrix room messages for reaction: %s", exc
                )
                break
        except Exception as exc:
            logger.debug("Failed to load Matrix room messages for reaction: %s", exc)
            break

        if not isinstance(response, dict):
            break
        chunk = response.get("chunk") or []
        if not isinstance(chunk, list) or not chunk:
            break
        for item in chunk:
            if isinstance(item, dict):
                collected.append(item)
        if len(collected) >= limit:
            break
        end = response.get("end")
        if not end or end == from_token:
            break
        from_token = str(end)
    return collected[:limit]


async def find_room_event_for_reaction(
    client: Any,
    room_id: str,
    message_content: str,
    *,
    anchor_time_ms: int | None = None,
    limit: int = 100,
    max_pages: int = 3,
) -> dict[str, Any] | None:
    """Find the nearest matching room event for a content-based reaction."""
    events = await collect_room_message_events(
        client,
        room_id,
        limit=limit,
        max_pages=max_pages,
    )
    return select_nearest_matching_event(
        events,
        message_content,
        anchor_time_ms=anchor_time_ms,
    )
