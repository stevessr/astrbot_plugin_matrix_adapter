"""Handler for Matrix room-member membership and profile changes."""

from astrbot.api.message_components import Plain

from ....constants import (
    MEMBERSHIP_BAN,
    MEMBERSHIP_INVITE,
    MEMBERSHIP_JOIN,
    MEMBERSHIP_KNOCK,
    MEMBERSHIP_LEAVE,
)
from .common import _format_member, _format_optional_reason, _get_prev_content


async def handle_room_member_change(receiver, chain, event, _: str):
    """
    Handle m.room.member membership/profile state events.

    These events are not normal chat messages, but rendering them as
    OtherMessage keeps joins/leaves/invites/bans visible to AstrBot workflows
    instead of emitting an empty system event.
    """
    content = event.content or {}
    prev_content = _get_prev_content(event)
    membership = content.get("membership") or "unknown"
    prev_membership = prev_content.get("membership")
    target_id = getattr(event, "state_key", None) or content.get("user_id")
    target_display = content.get("displayname") or content.get("display_name")
    target = _format_member(target_id, target_display)
    sender_id = getattr(event, "sender", None)
    sender = _format_member(sender_id)
    reason = _format_optional_reason(content.get("reason"))

    if membership == MEMBERSHIP_JOIN:
        if prev_membership == MEMBERSHIP_JOIN:
            changes: list[str] = []
            prev_display = prev_content.get("displayname") or prev_content.get(
                "display_name"
            )
            if target_display and target_display != prev_display:
                changes.append(f"display name to {target_display}")
            if content.get("avatar_url") and content.get(
                "avatar_url"
            ) != prev_content.get("avatar_url"):
                changes.append("avatar")
            if changes:
                text = f"[Room Member] {target} updated " + " and ".join(changes)
            else:
                text = f"[Room Member] {target} refreshed membership"
        else:
            text = f"[Room Member] {target} joined the room"
    elif membership == MEMBERSHIP_INVITE:
        text = f"[Room Member] {sender} invited {target}"
    elif membership == MEMBERSHIP_LEAVE:
        if sender_id and target_id and sender_id != target_id:
            text = f"[Room Member] {sender} removed {target} from the room{reason}"
        else:
            text = f"[Room Member] {target} left the room{reason}"
    elif membership == MEMBERSHIP_BAN:
        text = f"[Room Member] {sender} banned {target}{reason}"
    elif membership == MEMBERSHIP_KNOCK:
        text = f"[Room Member] {target} requested to join the room"
    else:
        text = f"[Room Member] {target} membership changed to: {membership}{reason}"

    chain.chain.append(Plain(text))
