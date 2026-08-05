"""m.room.tombstone state-event handler."""

from astrbot.api.message_components import Plain


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
