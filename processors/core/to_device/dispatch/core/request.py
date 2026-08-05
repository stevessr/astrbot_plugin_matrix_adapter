"""Room-key request cancellation collection."""

from ......constants import M_ROOM_KEY_REQUEST


def _collect_cancelled_requests(events: list) -> set[tuple[str, str, str]]:
    cancelled_requests: set[tuple[str, str, str]] = set()
    for event in events:
        if not isinstance(event, dict) or event.get("type") != M_ROOM_KEY_REQUEST:
            continue
        sender = event.get("sender")
        event_content = event.get("content")
        if not isinstance(sender, str) or not isinstance(event_content, dict):
            continue
        if event_content.get("action") != "request_cancellation":
            continue
        device_id = event_content.get("requesting_device_id")
        request_id = event_content.get("request_id")
        if (
            isinstance(device_id, str)
            and device_id
            and isinstance(request_id, str)
            and request_id
        ):
            cancelled_requests.add((sender, device_id, request_id))
    return cancelled_requests
