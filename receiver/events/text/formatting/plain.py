"""Plain-text and reply helpers for Matrix HTML fragments."""

import re
from html.parser import HTMLParser
from urllib.parse import unquote

from .patterns import (
    MENTION_HREF_RE,
    MENTION_MXID_RE,
    REPLY_BLOCK_RE,
    REPLY_EVENT_RE,
)


class _MatrixHTMLPlainParser(HTMLParser):
    """Small Matrix HTML-to-text parser with stable ordered-list semantics."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.list_stack: list[dict[str, object]] = []

    def _newline(self) -> None:
        if self.parts and not self.parts[-1].endswith("\n"):
            self.parts.append("\n")

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        attr_map = {str(key).lower(): value for key, value in attrs}
        if tag == "br":
            self.parts.append("\n")
            return
        if tag == "ol":
            start = 1
            raw_start = attr_map.get("start")
            if raw_start is not None:
                try:
                    start = int(str(raw_start).strip())
                except (TypeError, ValueError):
                    start = 1
            self.list_stack.append({"type": "ol", "next": start})
            return
        if tag == "ul":
            self.list_stack.append({"type": "ul"})
            return
        if tag == "li":
            self._newline()
            indent = "  " * max(0, len(self.list_stack) - 1)
            if self.list_stack and self.list_stack[-1].get("type") == "ol":
                current = int(self.list_stack[-1].get("next", 1))
                self.parts.append(f"{indent}{current}. ")
                self.list_stack[-1]["next"] = current + 1
            elif self.list_stack:
                self.parts.append(f"{indent}- ")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"p", "li"}:
            self._newline()
        elif tag in {"ol", "ul"}:
            if self.list_stack:
                self.list_stack.pop()
            self._newline()

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def text(self) -> str:
        return "".join(self.parts)


def _decode_matrix_to_segment(value: str | None) -> str:
    if not value:
        return ""
    return unquote(value)


def _plain_from_html(fragment: str) -> str:
    if not fragment:
        return ""
    parser = _MatrixHTMLPlainParser()
    try:
        parser.feed(fragment)
        parser.close()
        return parser.text()
    except Exception:
        # Formatted bodies are untrusted input. In the unlikely event that the
        # tolerant stdlib parser still fails, fall back to conservative tag
        # stripping rather than breaking message delivery.
        return re.sub(r"<[^>]+>", "", fragment)


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
