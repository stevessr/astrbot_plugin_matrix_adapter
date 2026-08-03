"""Reaction target matching and anchor-time helpers."""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Any

from ....constants import M_ROOM_MESSAGE, M_STICKER
from ..events import event_origin_server_ts_ms, extract_matrix_event_text
from ..time import parse_reaction_anchor_time_ms


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
