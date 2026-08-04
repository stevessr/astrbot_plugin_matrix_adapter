"""Formatted-body inline parsing into message components."""

from astrbot.api.message_components import Reply

from ..patterns import (
    INLINE_TAG_RE,
    MENTION_HREF_RE,
    MENTION_MXID_RE,
    REPLY_RE,
)
from ..plain import (
    _decode_matrix_to_segment,
    _extract_reply_info,
    _plain_from_html,
)
from .mentions import (
    _add_mention,
    _append_plain,
    _consume_leading_plain_mention,
)


def _append_formatted_body(
    chain,
    seen_mentions: set[str],
    receiver,
    formatted_body: str,
    appended_from_formatted: int,
) -> bool:
    """Append reply + inline HTML segments; return whether anything was added."""
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
    inline_added = False
    for match in INLINE_TAG_RE.finditer(sanitized):
        prefix = sanitized[pos : match.start()]
        prefix_text = _plain_from_html(prefix)
        if prefix_text:
            _append_plain(chain, prefix_text)
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
            _add_mention(chain, seen_mentions, user_id, anchor_text or user_id)
            inline_added = True
        elif anchor_text:
            _append_plain(chain, anchor_text)
            inline_added = True

        pos = match.end()

    tail = sanitized[pos:]
    tail_text = _plain_from_html(tail)
    if tail_text:
        _append_plain(chain, tail_text)
        inline_added = True

    if _consume_leading_plain_mention(
        chain, receiver, seen_mentions, appended_from_formatted
    ):
        inline_added = True
    return inline_added
