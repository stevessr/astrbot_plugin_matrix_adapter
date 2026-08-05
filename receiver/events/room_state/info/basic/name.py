"""m.room.name state-event handler."""

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
