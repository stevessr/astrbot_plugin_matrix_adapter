"""m.room.topic state-event handler."""

from astrbot.api.message_components import Plain

from ......room_topic import extract_room_topic


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
    new_topic, _html_topic = extract_room_topic(content)
    sender = getattr(event, "sender", "Someone")

    if new_topic:
        # Truncate long topics
        if len(new_topic) > 200:
            new_topic = new_topic[:200] + "..."
        text = f"[Room Info] {sender} changed the room topic to: {new_topic}"
    else:
        text = f"[Room Info] {sender} removed the room topic"

    chain.chain.append(Plain(text))
