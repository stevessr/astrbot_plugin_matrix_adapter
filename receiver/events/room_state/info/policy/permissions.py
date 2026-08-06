"""Room power-levels state-event handler."""

from astrbot.api.message_components import Plain


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


__all__ = ["handle_room_power_levels"]
