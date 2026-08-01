"""Handlers for Matrix space parent and child state events."""

from astrbot.api.message_components import Plain


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
        text = (
            f"[Space] {sender} added{canonical} parent space: {parent_room}{via_text}"
        )
    else:
        text = f"[Space] {sender} removed parent space: {parent_room}"
    chain.chain.append(Plain(text))
