"""
Handler for Matrix room state events (m.room.name, m.room.topic, m.room.encryption, etc.)
"""

from astrbot.api.message_components import Plain


def _format_member(user_id: str | None, display_name: str | None = None) -> str:
    user = str(user_id or "").strip()
    name = str(display_name or "").strip()
    if name and user and name != user:
        return f"{name} ({user})"
    return name or user or "Unknown user"


def _format_optional_reason(reason: object) -> str:
    if not reason:
        return ""
    return f": {reason}"


def _get_prev_content(event) -> dict:
    unsigned = getattr(event, "unsigned", None) or {}
    if not isinstance(unsigned, dict):
        return {}
    prev_content = unsigned.get("prev_content") or {}
    return prev_content if isinstance(prev_content, dict) else {}


def _format_limited_list(values: object, *, limit: int = 5) -> str:
    if not isinstance(values, list):
        return ""
    normalized = [str(item) for item in values if str(item)]
    if not normalized:
        return ""
    text = ", ".join(normalized[:limit])
    if len(normalized) > limit:
        text += f" (+{len(normalized) - limit} more)"
    return text


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


async def handle_space_child(receiver, chain, event, _: str):
    """Handle m.space.child state event."""
    content = event.content or {}
    child_room = getattr(event, "state_key", "") or "unknown room"
    sender = getattr(event, "sender", "Someone")
    if content:
        via = content.get("via") or []
        via_text = ""
        if isinstance(via, list) and via:
            via_text = f" via {', '.join(str(item) for item in via[:3])}"
            if len(via) > 3:
                via_text += f" (+{len(via) - 3} more)"
        suggested = " suggested" if content.get("suggested") is True else ""
        text = f"[Space] {sender} added{suggested} child room: {child_room}{via_text}"
    else:
        text = f"[Space] {sender} removed child room: {child_room}"
    chain.chain.append(Plain(text))


async def handle_space_parent(receiver, chain, event, _: str):
    """Handle m.space.parent state event."""
    content = event.content or {}
    parent_room = getattr(event, "state_key", "") or "unknown room"
    sender = getattr(event, "sender", "Someone")
    if content:
        via = content.get("via") or []
        via_text = ""
        if isinstance(via, list) and via:
            via_text = f" via {', '.join(str(item) for item in via[:3])}"
            if len(via) > 3:
                via_text += f" (+{len(via) - 3} more)"
        canonical = " canonical" if content.get("canonical") is True else ""
        text = f"[Space] {sender} added{canonical} parent space: {parent_room}{via_text}"
    else:
        text = f"[Space] {sender} removed parent space: {parent_room}"
    chain.chain.append(Plain(text))


async def handle_room_member_change(receiver, chain, event, _: str):
    """
    Handle m.room.member membership/profile state events.

    These events are not normal chat messages, but rendering them as
    OtherMessage keeps joins/leaves/invites/bans visible to AstrBot workflows
    instead of emitting an empty system event.
    """
    content = event.content or {}
    prev_content = _get_prev_content(event)
    membership = content.get("membership") or "unknown"
    prev_membership = prev_content.get("membership")
    target_id = getattr(event, "state_key", None) or content.get("user_id")
    target_display = content.get("displayname") or content.get("display_name")
    target = _format_member(target_id, target_display)
    sender_id = getattr(event, "sender", None)
    sender = _format_member(sender_id)
    reason = _format_optional_reason(content.get("reason"))

    if membership == "join":
        if prev_membership == "join":
            changes: list[str] = []
            prev_display = prev_content.get("displayname") or prev_content.get(
                "display_name"
            )
            if target_display and target_display != prev_display:
                changes.append(f"display name to {target_display}")
            if content.get("avatar_url") and content.get("avatar_url") != prev_content.get(
                "avatar_url"
            ):
                changes.append("avatar")
            if changes:
                text = f"[Room Member] {target} updated " + " and ".join(changes)
            else:
                text = f"[Room Member] {target} refreshed membership"
        else:
            text = f"[Room Member] {target} joined the room"
    elif membership == "invite":
        text = f"[Room Member] {sender} invited {target}"
    elif membership == "leave":
        if sender_id and target_id and sender_id != target_id:
            text = f"[Room Member] {sender} removed {target} from the room{reason}"
        else:
            text = f"[Room Member] {target} left the room{reason}"
    elif membership == "ban":
        text = f"[Room Member] {sender} banned {target}{reason}"
    elif membership == "knock":
        text = f"[Room Member] {target} requested to join the room"
    else:
        text = f"[Room Member] {target} membership changed to: {membership}{reason}"

    chain.chain.append(Plain(text))


# Map of state event types to their handlers
ROOM_STATE_HANDLERS = {
    "m.room.member": handle_room_member_change,
    "m.room.name": handle_room_name_change,
    "m.room.topic": handle_room_topic_change,
    "m.room.avatar": handle_room_avatar_change,
    "m.room.create": handle_room_create,
    "m.room.encryption": handle_room_encryption,
    "m.room.server_acl": handle_room_server_acl,
    "m.room.tombstone": handle_room_tombstone,
    "m.room.power_levels": handle_room_power_levels,
    "m.room.join_rules": handle_room_join_rules,
    "m.room.history_visibility": handle_room_history_visibility,
    "m.room.guest_access": handle_room_guest_access,
    "m.room.canonical_alias": handle_room_canonical_alias,
    "m.room.aliases": handle_room_aliases,
    "m.room.pinned_events": handle_room_pinned_events,
    "m.room.third_party_invite": handle_room_third_party_invite,
    "m.space.child": handle_space_child,
    "m.space.parent": handle_space_parent,
}
