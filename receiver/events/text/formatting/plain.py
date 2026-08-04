"""Plain-text and reply helpers for Matrix HTML fragments."""

import html
import re
from urllib.parse import unquote

from .patterns import (
    BREAK_RE,
    MENTION_HREF_RE,
    MENTION_MXID_RE,
    PARA_RE,
    REPLY_BLOCK_RE,
    REPLY_EVENT_RE,
    TAG_RE,
)


def _decode_matrix_to_segment(value: str | None) -> str:
    if not value:
        return ""
    return unquote(value)


def _plain_from_html(fragment: str) -> str:
    if not fragment:
        return ""
    fragment = BREAK_RE.sub("\n", fragment)
    fragment = PARA_RE.sub("\n", fragment)
    fragment = TAG_RE.sub("", fragment)
    return html.unescape(fragment)


def _extract_reply_info(
    html_text: str,
) -> tuple[str | None, str | None, str | None]:
    if not html_text:
        return None, None, None
    match = REPLY_BLOCK_RE.search(html_text)
    if not match:
        return None, None, None
    block = match.group(0)
    event_id = None
    event_match = REPLY_EVENT_RE.search(block)
    if event_match:
        candidate_event_id = _decode_matrix_to_segment(event_match.group(1))
        if candidate_event_id.startswith("$"):
            event_id = candidate_event_id

    sender_id = None
    for href_match in MENTION_HREF_RE.finditer(block):
        mxid = _decode_matrix_to_segment(href_match.group(1))
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
