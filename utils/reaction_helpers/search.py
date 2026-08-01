"""Room-history matching helpers for Matrix reactions."""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Any

from astrbot.api import logger

from ...constants import M_ROOM_MESSAGE, M_STICKER
from .events import event_origin_server_ts_ms, extract_matrix_event_text
from .keys import _maybe_await
from .time import parse_reaction_anchor_time_ms


def select_nearest_matching_event(
    events: Sequence[dict[str, Any]],
    message_content: str,
    *,
    anchor_time_ms: int | None = None,
) -> dict[str, Any] | None:
    """Pick the nearest event whose body exactly matches, else contains, the query.

    Matching priority:
    1. exact body match closest to ``anchor_time_ms``
    2. substring body match closest to ``anchor_time_ms``

    When ``anchor_time_ms`` is omitted, "nearest" falls back to the first match in
    the provided order (callers should pass newest-first history for that case).
    """
    query = str(message_content or "").strip()
    if not query:
        return None

    exact_candidates: list[tuple[int, int, dict[str, Any]]] = []
    contain_candidates: list[tuple[int, int, dict[str, Any]]] = []
    query_folded = query.casefold()

    for index, event in enumerate(events):
        if not isinstance(event, dict):
            continue
        event_type = str(event.get("type") or "")
        if event_type not in {M_ROOM_MESSAGE, M_STICKER}:
            continue
        text = extract_matrix_event_text(event)
        if not text:
            continue
        text_folded = text.casefold()
        if text_folded == query_folded:
            bucket = exact_candidates
        elif query_folded in text_folded:
            bucket = contain_candidates
        else:
            continue

        event_ts = event_origin_server_ts_ms(event)
        if anchor_time_ms is None or event_ts is None:
            distance = index
        else:
            distance = abs(event_ts - anchor_time_ms)
        bucket.append((distance, index, event))

    for bucket in (exact_candidates, contain_candidates):
        if not bucket:
            continue
        bucket.sort(key=lambda item: (item[0], item[1]))
        return bucket[0][2]
    return None


def default_anchor_time_ms(event: Any | None = None) -> int:
    """Resolve the default reaction search anchor time in milliseconds."""
    if event is not None:
        message_obj = getattr(event, "message_obj", None)
        for candidate in (
            getattr(message_obj, "timestamp", None),
            getattr(event, "created_at", None),
        ):
            parsed = parse_reaction_anchor_time_ms(candidate)
            if parsed is not None:
                # message_obj.timestamp is usually seconds; created_at is seconds float.
                return parsed
        raw_message = getattr(message_obj, "raw_message", None)
        if isinstance(raw_message, dict):
            raw_ts = event_origin_server_ts_ms(raw_message)
            if raw_ts is not None:
                return raw_ts
            nested = getattr(raw_message, "origin_server_ts", None)
            parsed = parse_reaction_anchor_time_ms(nested)
            if parsed is not None:
                return parsed
        elif raw_message is not None:
            raw_ts = event_origin_server_ts_ms(
                {
                    "origin_server_ts": getattr(raw_message, "origin_server_ts", None),
                }
            )
            if raw_ts is not None:
                return raw_ts
    return int(time.time() * 1000)


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
