"""Composable Matrix text formatting and event handlers."""

import html
import re
from urllib.parse import unquote

from astrbot.api.message_components import At, AtAll, Plain, Reply

from ....constants import MATRIX_HTML_FORMAT
from .formatting import (
    ANCHOR_RE,
    BREAK_RE,
    INLINE_TAG_RE,
    MENTION_HREF_RE,
    MENTION_MXID_RE,
    PARA_RE,
    PLAIN_MENTION_RE,
    REPLY_BLOCK_RE,
    REPLY_EVENT_RE,
    REPLY_RE,
    TAG_RE,
    _decode_matrix_to_segment,
    append_formatted_text,
    should_append_caption,
)
from .handler import handle_text

__all__ = [
    "ANCHOR_RE",
    "BREAK_RE",
    "INLINE_TAG_RE",
    "MATRIX_HTML_FORMAT",
    "MENTION_HREF_RE",
    "MENTION_MXID_RE",
    "PARA_RE",
    "PLAIN_MENTION_RE",
    "REPLY_BLOCK_RE",
    "REPLY_EVENT_RE",
    "REPLY_RE",
    "TAG_RE",
    "At",
    "AtAll",
    "Plain",
    "Reply",
    "_decode_matrix_to_segment",
    "append_formatted_text",
    "handle_text",
    "html",
    "re",
    "should_append_caption",
    "unquote",
]
