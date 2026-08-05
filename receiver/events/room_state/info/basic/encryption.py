"""m.room.encryption state-event handler."""

from astrbot.api.message_components import Plain


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
