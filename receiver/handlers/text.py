import html
import re

from astrbot.api.message_components import At, AtAll, Plain

MENTION_HREF_RE = re.compile(r'href="(?:https?://)?matrix\.to/#/(@[^"<> ]+)"')
MENTION_MXID_RE = re.compile(r'data-mxid="(@[^"<> ]+)"')
ANCHOR_RE = re.compile(r"<a\s+[^>]*>.*?</a>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")
BREAK_RE = re.compile(r"<\s*br\s*/?>", re.IGNORECASE)
PARA_RE = re.compile(r"</\s*p\s*>", re.IGNORECASE)
REPLY_RE = re.compile(r"<mx-reply>.*?</mx-reply>", re.IGNORECASE | re.DOTALL)


async def handle_text(receiver, chain, event, _: str):
    text = event.body or ""
    content = event.content or {}
    mentions = content.get("m.mentions") or {}
    formatted_body = content.get("formatted_body") or ""

    seen_mentions: set[str] = set()

    def _add_mention(user_id: str, display_name: str | None = None) -> None:
        if not user_id or user_id in seen_mentions:
            return
        seen_mentions.add(user_id)
        chain.chain.append(At(qq=user_id, name=display_name or user_id))

    def _plain_from_html(fragment: str) -> str:
        if not fragment:
            return ""
        fragment = BREAK_RE.sub("\n", fragment)
        fragment = PARA_RE.sub("\n", fragment)
        fragment = TAG_RE.sub("", fragment)
        return html.unescape(fragment)

    inline_added = False
    if formatted_body:
        sanitized = REPLY_RE.sub("", formatted_body)
        pos = 0
        for match in ANCHOR_RE.finditer(sanitized):
            prefix = sanitized[pos : match.start()]
            prefix_text = _plain_from_html(prefix)
            if prefix_text:
                chain.chain.append(Plain(prefix_text))
                inline_added = True

            anchor = match.group(0)
            user_id = None
            mxid_match = MENTION_MXID_RE.search(anchor)
            if mxid_match:
                user_id = mxid_match.group(1)
            else:
                href_match = MENTION_HREF_RE.search(anchor)
                if href_match:
                    user_id = href_match.group(1)

            anchor_text = _plain_from_html(anchor)
            if user_id and user_id.startswith("@"):
                _add_mention(user_id, anchor_text or user_id)
                inline_added = True
            elif anchor_text:
                chain.chain.append(Plain(anchor_text))
                inline_added = True

            pos = match.end()

        tail = sanitized[pos:]
        tail_text = _plain_from_html(tail)
        if tail_text:
            chain.chain.append(Plain(tail_text))
            inline_added = True

    if not inline_added:
        if isinstance(mentions, dict) and mentions.get("room"):
            chain.chain.append(AtAll())

        if isinstance(mentions, dict):
            for user_id in mentions.get("user_ids", []) or []:
                if isinstance(user_id, str) and user_id.startswith("@"):
                    _add_mention(user_id)

        if receiver.bot_name and text.startswith(f"@{receiver.bot_name}"):
            text = text[len(receiver.bot_name) + 1 :].lstrip()
            _add_mention(receiver.user_id, receiver.bot_name)

        if text:
            chain.chain.append(Plain(text))
