"""Basic room metadata state-event handlers."""

from astrbot.api.message_components import Plain


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


async def handle_room_create(receiver, chain, event, _: str):
    """Handle m.room.create state event."""
    content = event.content or {}
    sender = getattr(event, "sender", "Someone")
    room_version = content.get("room_version") or "unknown"
    room_type = content.get("type")
    federate = content.get("m.federate")

    details = [f"version={room_version}"]
    if room_type:
        details.append(f"type={room_type}")
    if federate is False:
        details.append("federation disabled")
    elif federate is True:
        details.append("federation enabled")

    chain.chain.append(
        Plain(f"[Room Info] {sender} created the room ({', '.join(details)})")
    )
