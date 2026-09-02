"""Event parsing orchestration."""

from typing import Any

from ....constants import REL_TYPE_REPLACE
from ..base import MatrixEvent
from .location import parse_location_event
from .messages import parse_message_event
from .state import parse_state_event


def _apply_bundled_replacement(event_data: dict[str, Any]) -> dict[str, Any]:
    """Apply a valid server-bundled ``m.replace`` aggregation.

    Homeservers keep the original content intact and bundle the most recent
    valid edit at ``unsigned.m.relations.m.replace``.  Clients are responsible
    for rendering that replacement.  Preserve the original event relation as
    required by the replacement specification and ignore any relation present
    inside ``m.new_content``.
    """
    if "state_key" in event_data:
        return event_data

    original_content = event_data.get("content")
    if not isinstance(original_content, dict):
        return event_data
    original_relation = original_content.get("m.relates_to")
    if (
        isinstance(original_relation, dict)
        and original_relation.get("rel_type") == REL_TYPE_REPLACE
    ):
        # An edit cannot itself be edited.
        return event_data

    unsigned = event_data.get("unsigned")
    relations = unsigned.get("m.relations") if isinstance(unsigned, dict) else None
    replacement = relations.get(REL_TYPE_REPLACE) if isinstance(relations, dict) else None
    if not isinstance(replacement, dict) or "state_key" in replacement:
        return event_data

    original_event_id = event_data.get("event_id")
    original_sender = event_data.get("sender")
    original_type = event_data.get("type")
    replacement_content = replacement.get("content")
    if not isinstance(replacement_content, dict):
        return event_data

    replacement_relation = replacement_content.get("m.relates_to")
    new_content = replacement_content.get("m.new_content")
    if not (
        isinstance(original_event_id, str)
        and original_event_id
        and replacement.get("sender") == original_sender
        and replacement.get("type") == original_type
        and isinstance(replacement_relation, dict)
        and replacement_relation.get("rel_type") == REL_TYPE_REPLACE
        and replacement_relation.get("event_id") == original_event_id
        and isinstance(new_content, dict)
    ):
        return event_data

    applied_content = dict(new_content)
    # m.new_content does not get to replace the original event relationship.
    applied_content.pop("m.relates_to", None)
    if isinstance(original_relation, dict):
        applied_content["m.relates_to"] = dict(original_relation)

    normalized = dict(event_data)
    normalized["content"] = applied_content
    return normalized


def parse_event(event_data: dict[str, Any], room_id: str) -> MatrixEvent:
    """
    Parse event data into appropriate event type.

    Args:
        event_data: Raw event data from Matrix.
        room_id: Room ID the event belongs to.

    Returns:
        Parsed event object.
    """
    event_data = _apply_bundled_replacement(event_data)
    event_type = event_data.get("type", "")
    content = event_data.get("content", {})

    # Standalone m.replace events deliberately keep their top-level fallback
    # and m.new_content here.  The message processor performs ordering and
    # edit normalization after decryption, which is required for encrypted
    # replacement events and out-of-order /sync delivery.
    parsed_event = parse_message_event(event_data, room_id, event_type, content)
    if parsed_event is not None:
        return parsed_event

    parsed_event = parse_location_event(event_data, room_id, event_type, content)
    if parsed_event is not None:
        return parsed_event

    parsed_event = parse_state_event(event_data, room_id, event_type, content)
    if parsed_event is not None:
        return parsed_event

    return MatrixEvent.from_dict(event_data, room_id)


__all__ = ["parse_event", "_apply_bundled_replacement"]
