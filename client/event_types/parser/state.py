"""Membership and redaction event parsing branches."""

from ....constants import M_ROOM_MEMBER, M_ROOM_REDACTION, MEMBERSHIP_INVITE
from ..base import MatrixEvent
from ..messages import InviteEvent, RoomMessageEvent


def parse_state_event(
    event_data: dict, room_id: str, event_type: str, content: dict
) -> MatrixEvent | None:
    """Parse member invites and redaction events."""
    if event_type == M_ROOM_MEMBER and content.get("membership") == MEMBERSHIP_INVITE:
        return InviteEvent.from_dict(event_data, room_id)
    if event_type == M_ROOM_REDACTION:
        redaction_content = dict(content)
        if "redacts" not in redaction_content and event_data.get("redacts"):
            redaction_content["redacts"] = event_data.get("redacts")
        event_data = dict(event_data)
        event_data["content"] = redaction_content
        event = RoomMessageEvent.from_dict(event_data, room_id)
        event.msgtype = "m.redaction"
        event.body = redaction_content.get("reason", "")
        return event
    return None
