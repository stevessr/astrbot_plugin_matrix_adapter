"""Pinned-event ID normalization."""

from collections.abc import Iterable


def normalize_pinned_event_ids(event_ids: Iterable[object] | object) -> list[str]:
    if isinstance(event_ids, str):
        values = [event_ids]
    else:
        try:
            values = list(event_ids)  # type: ignore[arg-type]
        except TypeError:
            values = [event_ids]

    pinned: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value is None:
            continue
        event_id = str(value).strip()
        if not event_id or event_id in seen:
            continue
        pinned.append(event_id)
        seen.add(event_id)
    return pinned
