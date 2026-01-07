from astrbot.api.message_components import At, Plain


async def handle_text(receiver, chain, event, _: str):
    text = event.body

    if receiver.bot_name and text.startswith(f"@{receiver.bot_name}"):
        text = text[len(receiver.bot_name) + 1 :].lstrip()
        chain.chain.append(At(user_id=receiver.user_id))

    if text:
        chain.chain.append(Plain(text))
