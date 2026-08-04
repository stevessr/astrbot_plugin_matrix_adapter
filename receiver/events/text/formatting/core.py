"""Formatted Matrix text -> message chain conversion."""

from astrbot.api.message_components import At, AtAll, Plain, Reply

from .....constants import MATRIX_HTML_FORMAT
from .patterns import (
    INLINE_TAG_RE,
    MENTION_HREF_RE,
    MENTION_MXID_RE,
    PLAIN_MENTION_RE,
    REPLY_RE,
)
from .plain import _decode_matrix_to_segment, _extract_reply_info, _plain_from_html


def should_append_caption(content: dict, filename: str | None = None) -> bool:
    body = content.get("body") or ""
    if not body:
        return False
    if content.get("formatted_body"):
        return True
    if filename and body != filename:
        return True
    return False


def append_formatted_text(
    receiver,
    chain,
    text: str,
    content: dict,
) -> None:
    text = text or ""
    content = content or {}
    mentions = content.get("m.mentions") or {}
    format_type = content.get("format") or ""
    formatted_body = content.get("formatted_body") or ""
    if format_type != MATRIX_HTML_FORMAT:
        formatted_body = ""

    seen_mentions: set[str] = set()

    def _append_plain(value: str) -> None:
        if not value:
            return
        if chain.chain and isinstance(chain.chain[-1], Plain):
            chain.chain[-1].text += value
        else:
            chain.chain.append(Plain(value))

    def _add_mention(user_id: str, display_name: str | None = None) -> None:
        if not user_id or user_id in seen_mentions:
            return
        seen_mentions.add(user_id)
        chain.chain.append(At(qq=user_id, name=display_name or user_id))

    def _consume_leading_plain_mention(start_index: int) -> bool:
        if start_index >= len(chain.chain):
            return False
        component = chain.chain[start_index]
        if not isinstance(component, Plain) or not receiver.bot_name:
            return False
        plain_mention_match = PLAIN_MENTION_RE.match(component.text)
        if not plain_mention_match:
            return False
        mention_name = plain_mention_match.group(1).strip()
        if mention_name != receiver.bot_name:
            return False

        remaining_text = component.text[plain_mention_match.end() :].lstrip()
        del chain.chain[start_index]
        _add_mention(receiver.user_id, receiver.bot_name)
        if remaining_text:
            chain.chain.insert(start_index + 1, Plain(remaining_text))
        return True

    inline_added = False
    appended_from_formatted = len(chain.chain)
    if formatted_body:
        if not any(isinstance(component, Reply) for component in chain.chain):
            reply_event_id, reply_sender, reply_text = _extract_reply_info(
                formatted_body
            )
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
                _append_plain(prefix_text)
                inline_added = True

            inline_tag = match.group(0)
            user_id = None
            mxid_match = MENTION_MXID_RE.search(inline_tag)
            if mxid_match:
                user_id = _decode_matrix_to_segment(mxid_match.group(1))
            else:
                href_match = MENTION_HREF_RE.search(inline_tag)
                if href_match:
                    user_id = _decode_matrix_to_segment(href_match.group(1))

            anchor_text = _plain_from_html(inline_tag)
            if user_id and user_id.startswith("@"):
                _add_mention(user_id, anchor_text or user_id)
                inline_added = True
            elif anchor_text:
                _append_plain(anchor_text)
                inline_added = True

            pos = match.end()

        tail = sanitized[pos:]
        tail_text = _plain_from_html(tail)
        if tail_text:
            _append_plain(tail_text)
            inline_added = True

        if _consume_leading_plain_mention(appended_from_formatted):
            inline_added = True

    if isinstance(mentions, dict) and mentions.get("room"):
        chain.chain.append(AtAll())

    if isinstance(mentions, dict):
        for user_id in mentions.get("user_ids", []) or []:
            if isinstance(user_id, str) and user_id.startswith("@"):
                _add_mention(user_id)

    if not inline_added:
        # Some clients only emit plain-text MXID mentions without m.mentions.
        if receiver.user_id and receiver.user_id in text:
            _add_mention(receiver.user_id, receiver.bot_name or receiver.user_id)
            text = text.replace(receiver.user_id, "", 1).lstrip()

        if receiver.bot_name and text.startswith(f"@{receiver.bot_name}"):
            text = text[len(receiver.bot_name) + 1 :].lstrip()
            _add_mention(receiver.user_id, receiver.bot_name)

        plain_mention_match = PLAIN_MENTION_RE.match(text)
        if plain_mention_match and receiver.bot_name:
            mention_name = plain_mention_match.group(1).strip()
            if mention_name == receiver.bot_name:
                _add_mention(receiver.user_id, receiver.bot_name)
                text = text[plain_mention_match.end() :].lstrip()

        if text:
            _append_plain(text)
