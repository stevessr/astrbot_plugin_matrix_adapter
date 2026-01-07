from astrbot.api.message_components import Plain


async def handle_reaction(receiver, chain, event, _: str):
    relates_to = event.content.get("m.relates_to", {})
    emoji = relates_to.get("key") or event.body or ""
    target = relates_to.get("event_id", "")

    if emoji and target:
        text = f"[reaction] {emoji} -> {target}"
    elif emoji:
        text = f"[reaction] {emoji}"
    elif target:
        text = f"[reaction] -> {target}"
    else:
        text = "[reaction]"

    chain.chain.append(Plain(text))
