"""Room join-rules, history-visibility, and guest-access handlers."""

from astrbot.api.message_components import Plain


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


async def handle_room_guest_access(receiver, chain, event, _: str):
    """Handle m.room.guest_access state event."""
    content = event.content or {}
    guest_access = content.get("guest_access", "unknown")
    sender = getattr(event, "sender", "Someone")

    access_descriptions = {
        "can_join": "guests can join",
        "forbidden": "guests cannot join",
    }
    description = access_descriptions.get(guest_access, guest_access)
    chain.chain.append(
        Plain(f"[Room Info] {sender} changed guest access to: {description}")
    )


__all__ = [
    "handle_room_guest_access",
    "handle_room_history_visibility",
    "handle_room_join_rules",
]
