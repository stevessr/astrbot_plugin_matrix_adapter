from astrbot.api.message_components import Plain


async def handle_unknown(receiver, chain, event, msgtype: str):
    chain.chain.append(Plain(event.body or f"[Unknown message type: {msgtype}]"))
