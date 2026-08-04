"""HTML and mention formatting helpers for Matrix text events.

Public symbols re-exported for backward compatibility.
"""

import html
import re
from urllib.parse import unquote

from .core import append_formatted_text, should_append_caption
from .patterns import (
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
)
from .plain import _decode_matrix_to_segment

__all__ = [
    "ANCHOR_RE",
    "BREAK_RE",
    "INLINE_TAG_RE",
    "MENTION_HREF_RE",
    "MENTION_MXID_RE",
    "PARA_RE",
    "PLAIN_MENTION_RE",
    "REPLY_BLOCK_RE",
    "REPLY_EVENT_RE",
    "REPLY_RE",
    "TAG_RE",
    "_decode_matrix_to_segment",
    "append_formatted_text",
    "html",
    "re",
    "should_append_caption",
    "unquote",
]
