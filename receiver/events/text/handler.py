"""Inbound Matrix text event handler."""

from astrbot.api.message_components import Plain

from .formatting import append_formatted_text


async def handle_text(receiver, chain, event, msgtype: str):
    content = event.content or {}
    resolved_msgtype = (
        msgtype or content.get("msgtype") or getattr(event, "msgtype", "")
    )
    body = event.body or content.get("body", "")
    if resolved_msgtype == "m.emote":
        sender = getattr(event, "sender", "") or "Someone"
        chain.chain.append(Plain(f"* {sender} "))
        append_formatted_text(receiver, chain, body, content)
        return

    append_formatted_text(receiver, chain, body, content)
