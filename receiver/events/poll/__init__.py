"""Inbound Matrix poll handlers and content helpers."""

from astrbot.api.message_components import Plain

from .handlers import handle_poll_end, handle_poll_response, handle_poll_start
from .parsing import (
    _extract_poll_answers,
    _extract_poll_selections,
    _extract_text_repr,
    _get_poll_content,
)

__all__ = [
    "Plain",
    "_extract_poll_answers",
    "_extract_poll_selections",
    "_extract_text_repr",
    "_get_poll_content",
    "handle_poll_end",
    "handle_poll_response",
    "handle_poll_start",
]
