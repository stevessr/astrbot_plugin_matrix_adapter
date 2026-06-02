"""
Handler for Matrix room state events (m.room.name, m.room.topic, m.room.encryption, etc.)
"""

from astrbot.api.message_components import Plain


def _format_member(user_id: str | None, display_name: str | None = None) -> str:
    user = str(user_id or "").strip()
    name = str(display_name or "").strip()
    if name and user and name != user:
        return f"{name} ({user})"
    return name or user or "Unknown user"


def _format_optional_reason(reason: object) -> str:
    if not reason:
        return ""
    return f": {reason}"


def _get_prev_content(event) -> dict:
    unsigned = getattr(event, "unsigned", None) or {}
    if not isinstance(unsigned, dict):
        return {}
    prev_content = unsigned.get("prev_content") or {}
    return prev_content if isinstance(prev_content, dict) else {}


async def handle_room_name_change(receiver, chain, event, _: str):
    """
    Handle m.room.name state event

    Args:
        receiver: MatrixReceiver instance
        chain: MessageChain to append to
        event: Matrix event object
        _: Event type (unused)
    """
    content = event.content or {}
    new_name = content.get("name", "")
    sender = getattr(event, "sender", "Someone")

    if new_name:
        text = f"[Room Info] {sender} changed the room name to: {new_name}"
    else:
        text = f"[Room Info] {sender} removed the room name"

    chain.chain.append(Plain(text))


async def handle_room_topic_change(receiver, chain, event, _: str):
    """
    Handle m.room.topic state event

    Args:
        receiver: MatrixReceiver instance
        chain: MessageChain to append to
        event: Matrix event object
        _: Event type (unused)
    """
    content = event.content or {}
    new_topic = content.get("topic", "")
    sender = getattr(event, "sender", "Someone")

    if new_topic:
        # Truncate long topics
        if len(new_topic) > 200:
            new_topic = new_topic[:200] + "..."
        text = f"[Room Info] {sender} changed the room topic to: {new_topic}"
    else:
        text = f"[Room Info] {sender} removed the room topic"

    chain.chain.append(Plain(text))


async def handle_room_avatar_change(receiver, chain, event, _: str):
    """
    Handle m.room.avatar state event

    Args:
        receiver: MatrixReceiver instance
        chain: MessageChain to append to
        event: Matrix event object
        _: Event type (unused)
    """
    content = event.content or {}
    avatar_url = content.get("url")
    sender = getattr(event, "sender", "Someone")

    if avatar_url:
        text = f"[Room Info] {sender} changed the room avatar"
    else:
        text = f"[Room Info] {sender} removed the room avatar"

    chain.chain.append(Plain(text))


async def handle_room_encryption(receiver, chain, event, _: str):
    """
    Handle m.room.encryption state event (room became encrypted)

    Args:
        receiver: MatrixReceiver instance
        chain: MessageChain to append to
        event: Matrix event object
        _: Event type (unused)
    """
    content = event.content or {}
    algorithm = content.get("algorithm", "unknown")
    sender = getattr(event, "sender", "Someone")

    text = (
        f"[Room Info] {sender} enabled end-to-end encryption (algorithm: {algorithm})"
    )
    chain.chain.append(Plain(text))


async def handle_room_tombstone(receiver, chain, event, _: str):
    """
    Handle m.room.tombstone state event (room was upgraded/deprecated)

    Args:
        receiver: MatrixReceiver instance
        chain: MessageChain to append to
        event: Matrix event object
        _: Event type (unused)
    """
    content = event.content or {}
    body = content.get("body", "This room has been upgraded")
    replacement_room = content.get("replacement_room", "")
    sender = getattr(event, "sender", "Someone")

    text = f"[Room Info] {sender} marked this room as deprecated: {body}"
    if replacement_room:
        text += f" (new room: {replacement_room})"

    chain.chain.append(Plain(text))


async def handle_room_power_levels(receiver, chain, event, _: str):
    """
    Handle m.room.power_levels state event

    Args:
        receiver: MatrixReceiver instance
        chain: MessageChain to append to
        event: Matrix event object
        _: Event type (unused)
    """
    sender = getattr(event, "sender", "Someone")
    text = f"[Room Info] {sender} updated room permissions"
    chain.chain.append(Plain(text))


async def handle_room_join_rules(receiver, chain, event, _: str):
    """
    Handle m.room.join_rules state event

    Args:
        receiver: MatrixReceiver instance
        chain: MessageChain to append to
        event: Matrix event object
        _: Event type (unused)
    """
    content = event.content or {}
    join_rule = content.get("join_rule", "unknown")
    sender = getattr(event, "sender", "Someone")

    rule_descriptions = {
        "public": "anyone can join",
        "invite": "invite only",
        "knock": "anyone can request to join",
        "restricted": "restricted (space members only)",
        "knock_restricted": "restricted knock",
        "private": "private",
    }
    description = rule_descriptions.get(join_rule, join_rule)

    text = f"[Room Info] {sender} changed join rules to: {description}"
    chain.chain.append(Plain(text))


async def handle_room_history_visibility(receiver, chain, event, _: str):
    """
    Handle m.room.history_visibility state event

    Args:
        receiver: MatrixReceiver instance
        chain: MessageChain to append to
        event: Matrix event object
        _: Event type (unused)
    """
    content = event.content or {}
    visibility = content.get("history_visibility", "unknown")
    sender = getattr(event, "sender", "Someone")

    visibility_descriptions = {
        "world_readable": "anyone can read",
        "shared": "members can read (from when they joined)",
        "invited": "members can read (from when they were invited)",
        "joined": "members can read (only since they joined)",
    }
    description = visibility_descriptions.get(visibility, visibility)

    text = f"[Room Info] {sender} changed history visibility to: {description}"
    chain.chain.append(Plain(text))


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

    if membership == "join":
        if prev_membership == "join":
            changes: list[str] = []
            prev_display = prev_content.get("displayname") or prev_content.get(
                "display_name"
            )
            if target_display and target_display != prev_display:
                changes.append(f"display name to {target_display}")
            if content.get("avatar_url") and content.get("avatar_url") != prev_content.get(
                "avatar_url"
            ):
                changes.append("avatar")
            if changes:
                text = f"[Room Member] {target} updated " + " and ".join(changes)
            else:
                text = f"[Room Member] {target} refreshed membership"
        else:
            text = f"[Room Member] {target} joined the room"
    elif membership == "invite":
        text = f"[Room Member] {sender} invited {target}"
    elif membership == "leave":
        if sender_id and target_id and sender_id != target_id:
            text = f"[Room Member] {sender} removed {target} from the room{reason}"
        else:
            text = f"[Room Member] {target} left the room{reason}"
    elif membership == "ban":
        text = f"[Room Member] {sender} banned {target}{reason}"
    elif membership == "knock":
        text = f"[Room Member] {target} requested to join the room"
    else:
        text = f"[Room Member] {target} membership changed to: {membership}{reason}"

    chain.chain.append(Plain(text))


# Map of state event types to their handlers
ROOM_STATE_HANDLERS = {
    "m.room.member": handle_room_member_change,
    "m.room.name": handle_room_name_change,
    "m.room.topic": handle_room_topic_change,
    "m.room.avatar": handle_room_avatar_change,
    "m.room.encryption": handle_room_encryption,
    "m.room.tombstone": handle_room_tombstone,
    "m.room.power_levels": handle_room_power_levels,
    "m.room.join_rules": handle_room_join_rules,
    "m.room.history_visibility": handle_room_history_visibility,
}
