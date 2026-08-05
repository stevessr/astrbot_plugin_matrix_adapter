"""To-device event ordering: room keys before sibling requests."""

from ......constants import M_ROOM_ENCRYPTED, M_ROOM_KEY_REQUEST


def _sort_to_device_events(events: list) -> list:
    key_event_types = {M_ROOM_ENCRYPTED}
    return sorted(
        events,
        key=lambda event: (
            0
            if isinstance(event, dict) and event.get("type") in key_event_types
            else (
                1
                if isinstance(event, dict)
                and event.get("type") == M_ROOM_KEY_REQUEST
                and (event.get("content") or {}).get("action") == "request"
                else 2
            )
        ),
    )
