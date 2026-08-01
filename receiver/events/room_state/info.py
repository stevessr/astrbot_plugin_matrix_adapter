"""Handlers for room metadata and access-policy state events."""

from astrbot.api.message_components import Plain

from .common import _format_limited_list


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


async def handle_room_server_acl(receiver, chain, event, _: str):
    """Handle m.room.server_acl state event."""
    content = event.content or {}
    sender = getattr(event, "sender", "Someone")
    if not content:
        chain.chain.append(Plain(f"[Room Info] {sender} removed server ACL rules"))
        return

    allow = _format_limited_list(content.get("allow"))
    deny = _format_limited_list(content.get("deny"))
    allow_ip_literals = content.get("allow_ip_literals")
    parts: list[str] = []
    if allow:
        parts.append(f"allow: {allow}")
    if deny:
        parts.append(f"deny: {deny}")
    if allow_ip_literals is not None:
        parts.append(f"allow_ip_literals={bool(allow_ip_literals)}")
    if not parts:
        parts.append("rules updated")
    chain.chain.append(
        Plain(f"[Room Info] {sender} updated server ACL ({'; '.join(parts)})")
    )


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


async def handle_room_canonical_alias(receiver, chain, event, _: str):
    """Handle m.room.canonical_alias state event."""
    content = event.content or {}
    alias = content.get("alias") or ""
    alt_aliases = content.get("alt_aliases") or []
    sender = getattr(event, "sender", "Someone")

    if alias:
        text = f"[Room Info] {sender} changed canonical alias to: {alias}"
    else:
        text = f"[Room Info] {sender} removed the canonical alias"
    if isinstance(alt_aliases, list) and alt_aliases:
        text += f" (alt aliases: {', '.join(str(item) for item in alt_aliases[:5])})"
        if len(alt_aliases) > 5:
            text += f" (+{len(alt_aliases) - 5} more)"
    chain.chain.append(Plain(text))


async def handle_room_pinned_events(receiver, chain, event, _: str):
    """Handle m.room.pinned_events state event."""
    content = event.content or {}
    pinned = content.get("pinned") or []
    sender = getattr(event, "sender", "Someone")
    if not isinstance(pinned, list):
        pinned = []
    count = len(pinned)
    if count == 0:
        text = f"[Room Info] {sender} removed all pinned events"
    elif count == 1:
        text = f"[Room Info] {sender} pinned 1 event"
    else:
        text = f"[Room Info] {sender} pinned {count} events"
    chain.chain.append(Plain(text))


async def handle_room_third_party_invite(receiver, chain, event, _: str):
    """Handle m.room.third_party_invite state event."""
    content = event.content or {}
    sender = getattr(event, "sender", "Someone")
    token = getattr(event, "state_key", "") or ""
    display_name = content.get("display_name") or content.get("displayname") or token

    if content:
        if token and display_name and display_name != token:
            text = (
                f"[Room Invite] {sender} added third-party invite for "
                f"{display_name} ({token})"
            )
        else:
            text = f"[Room Invite] {sender} added third-party invite for {display_name}"
    else:
        target = f" for {token}" if token else ""
        text = f"[Room Invite] {sender} removed third-party invite{target}"
    chain.chain.append(Plain(text))


async def handle_room_aliases(receiver, chain, event, _: str):
    """Handle m.room.aliases state event."""
    content = event.content or {}
    aliases = content.get("aliases") or []
    sender = getattr(event, "sender", "Someone")
    server = getattr(event, "state_key", "") or ""

    if not isinstance(aliases, list):
        aliases = []

    suffix = f" for {server}" if server else ""
    if aliases:
        alias_text = ", ".join(str(item) for item in aliases[:5])
        text = f"[Room Info] {sender} updated room aliases{suffix}: {alias_text}"
        if len(aliases) > 5:
            text += f" (+{len(aliases) - 5} more)"
    else:
        text = f"[Room Info] {sender} removed room aliases{suffix}"
    chain.chain.append(Plain(text))
