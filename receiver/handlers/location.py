from astrbot.api.message_components import Plain


async def handle_location(receiver, chain, event, _: str):
    geo_uri = event.content.get("geo_uri", "")
    body = event.body or event.content.get("body", "")
    if body and geo_uri:
        text = f"[位置] {body} {geo_uri}"
    elif body:
        text = f"[位置] {body}"
    elif geo_uri:
        text = f"[位置] {geo_uri}"
    else:
        text = "[位置]"
    chain.chain.append(Plain(text))
