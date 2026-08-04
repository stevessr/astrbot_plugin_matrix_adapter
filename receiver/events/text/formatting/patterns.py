"""Compiled regex patterns for Matrix HTML/mention parsing."""

import re

MENTION_HREF_RE = re.compile(
    r"""href\s*=\s*[\"'](?:https?://)?matrix\.to/#/([^/\"'<> ?#]+)""",
    re.IGNORECASE,
)
MENTION_MXID_RE = re.compile(
    r"""data-mxid\s*=\s*[\"'](@[^\"'<> ]+)[\"']""",
    re.IGNORECASE,
)
ANCHOR_RE = re.compile(r"<a\s+[^>]*>.*?</a>", re.IGNORECASE | re.DOTALL)
INLINE_TAG_RE = re.compile(r"<(a|span)\s+[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")
BREAK_RE = re.compile(r"<\s*br\s*/?>", re.IGNORECASE)
PARA_RE = re.compile(r"</\s*p\s*>", re.IGNORECASE)
REPLY_RE = re.compile(r"<mx-reply>.*?</mx-reply>", re.IGNORECASE | re.DOTALL)
REPLY_BLOCK_RE = re.compile(r"<mx-reply>.*?</mx-reply>", re.IGNORECASE | re.DOTALL)
REPLY_EVENT_RE = re.compile(
    r"""href\s*=\s*[\"'](?:https?://)?matrix\.to/#/[^/\"'<> ?#]+/([^/\"'<> ?#]+)""",
    re.IGNORECASE,
)
PLAIN_MENTION_RE = re.compile(r"^@\[([^\]\r\n]+)\](?=\s|$)")
