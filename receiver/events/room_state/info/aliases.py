"""Room alias, pin, and third-party invite handlers."""

from astrbot.api.message_components import Plain


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
