"""m.room.create state-event handler."""

from astrbot.api.message_components import Plain


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
