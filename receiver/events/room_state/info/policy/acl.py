"""Room server-ACL state-event handler."""

from astrbot.api.message_components import Plain

from ...common import _format_limited_list


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


__all__ = ["handle_room_server_acl"]
