import re

from astrbot.api.message_components import At, AtAll, Plain

MENTION_HREF_RE = re.compile(r'href="(?:https?://)?matrix\.to/#/(@[^"<> ]+)"')
MENTION_MXID_RE = re.compile(r'data-mxid="(@[^"<> ]+)"')


async def handle_text(receiver, chain, event, _: str):
    text = event.body or ""
    content = event.content or {}
    mentions = content.get("m.mentions") or {}

    seen_mentions: set[str] = set()

    def _add_mention(user_id: str, display_name: str | None = None) -> None:
        if not user_id or user_id in seen_mentions:
            return
        seen_mentions.add(user_id)
        chain.chain.append(At(qq=user_id, name=display_name or user_id))

    if isinstance(mentions, dict) and mentions.get("room"):
        chain.chain.append(AtAll())

    if isinstance(mentions, dict):
        for user_id in mentions.get("user_ids", []) or []:
            if isinstance(user_id, str) and user_id.startswith("@"):
                _add_mention(user_id)

    formatted_body = content.get("formatted_body") or ""
    if formatted_body:
        for match in MENTION_MXID_RE.finditer(formatted_body):
            user_id = match.group(1)
            if user_id.startswith("@"):
                _add_mention(user_id)
        for match in MENTION_HREF_RE.finditer(formatted_body):
            user_id = match.group(1)
            if user_id.startswith("@"):
                _add_mention(user_id)

    if receiver.bot_name and text.startswith(f"@{receiver.bot_name}"):
        text = text[len(receiver.bot_name) + 1 :].lstrip()
        _add_mention(receiver.user_id, receiver.bot_name)

    if text:
        chain.chain.append(Plain(text))
