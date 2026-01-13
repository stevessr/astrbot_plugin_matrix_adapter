import html
import re

from astrbot.api.message_components import At, AtAll, Plain, Reply

MENTION_HREF_RE = re.compile(r'href="(?:https?://)?matrix\.to/#/(@[^"<> ]+)"')
MENTION_MXID_RE = re.compile(r'data-mxid="(@[^"<> ]+)"')
ANCHOR_RE = re.compile(r"<a\s+[^>]*>.*?</a>", re.IGNORECASE | re.DOTALL)
INLINE_TAG_RE = re.compile(r"<(a|span)\s+[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")
BREAK_RE = re.compile(r"<\s*br\s*/?>", re.IGNORECASE)
PARA_RE = re.compile(r"</\s*p\s*>", re.IGNORECASE)
REPLY_RE = re.compile(r"<mx-reply>.*?</mx-reply>", re.IGNORECASE | re.DOTALL)
REPLY_BLOCK_RE = re.compile(r"<mx-reply>.*?</mx-reply>", re.IGNORECASE | re.DOTALL)
REPLY_EVENT_RE = re.compile(
    r'href="(?:https?://)?matrix\.to/#/[^"<> ]+/(\$[^"<> ]+)"', re.IGNORECASE
)


async def handle_text(receiver, chain, event, _: str):
    text = event.body or ""
    content = event.content or {}
    mentions = content.get("m.mentions") or {}
    format_type = content.get("format") or ""
    formatted_body = content.get("formatted_body") or ""
    if format_type != "org.matrix.custom.html":
        formatted_body = ""

    # 豁免 ! 开头的命令，自动转换为 / 开头
    if text.startswith("!"):
        text = "/" + text[1:]

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

    def _extract_reply_info(html_text: str) -> tuple[str | None, str | None, str | None]:
        if not html_text:
            return None, None, None
        match = REPLY_BLOCK_RE.search(html_text)
        if not match:
            return None, None, None
        block = match.group(0)
        event_id = None
        event_match = REPLY_EVENT_RE.search(block)
        if event_match:
            event_id = event_match.group(1)

        sender_id = None
        for href_match in MENTION_HREF_RE.finditer(block):
            mxid = href_match.group(1)
            if mxid and mxid.startswith("@"):
                sender_id = mxid
                break
        if not sender_id:
            mxid_match = MENTION_MXID_RE.search(block)
            if mxid_match:
                sender_id = mxid_match.group(1)

        body_fragment = re.sub(
            r"^.*?<\s*br\s*/?>", "", block, flags=re.IGNORECASE | re.DOTALL
        )
        body_text = _plain_from_html(body_fragment).strip()
        return event_id, sender_id, body_text

    inline_added = False
    if formatted_body:
        if not any(isinstance(component, Reply) for component in chain.chain):
            reply_event_id, reply_sender, reply_text = _extract_reply_info(formatted_body)
            if reply_event_id:
                chain.chain.append(
                    Reply(
                        id=reply_event_id,
                        sender_id=reply_sender or "",
                        sender_nickname=reply_sender or "",
                        message_str=reply_text or "",
                    )
                )

        sanitized = REPLY_RE.sub("", formatted_body)
        pos = 0
        for match in INLINE_TAG_RE.finditer(sanitized):
            prefix = sanitized[pos : match.start()]
            prefix_text = _plain_from_html(prefix)
            if prefix_text:
                chain.chain.append(Plain(prefix_text))
                inline_added = True

            inline_tag = match.group(0)
            user_id = None
            mxid_match = MENTION_MXID_RE.search(inline_tag)
            if mxid_match:
                user_id = mxid_match.group(1)
            else:
                href_match = MENTION_HREF_RE.search(inline_tag)
                if href_match:
                    user_id = href_match.group(1)

            anchor_text = _plain_from_html(inline_tag)
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
