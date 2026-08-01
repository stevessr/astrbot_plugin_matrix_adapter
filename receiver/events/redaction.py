from astrbot.api.message_components import Plain, Reply


def _build_redaction_text(event) -> str:
    content = event.content or {}
    reason = content.get("reason") or ""
    if reason:
        return f"[消息已撤回] {reason}"
    return "[消息已撤回]"


async def handle_redaction(receiver, chain, event, _: str):
    content = event.content or {}
    redacts = content.get("redacts") or getattr(event, "redacts", None)
    if redacts:
        chain.chain.append(Reply(id=redacts))
    chain.chain.append(Plain(_build_redaction_text(event)))
