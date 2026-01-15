from astrbot.api.message_components import Plain


def _build_redaction_text(event) -> str:
    content = event.content or {}
    redacts = content.get("redacts") or getattr(event, "redacts", None)
    reason = content.get("reason") or ""
    if redacts and reason:
        return f"[消息已撤回：{redacts}] {reason}"
    if redacts:
        return f"[消息已撤回：{redacts}]"
    if reason:
        return f"[消息已撤回] {reason}"
    return "[消息已撤回]"


async def handle_redaction(receiver, chain, event, _: str):
    chain.chain.append(Plain(_build_redaction_text(event)))
