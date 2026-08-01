"""Compatibility exports for the split Matrix message mixins."""

from .message import MessageMixin
from .message.send import (
    _build_live_message_metadata,
    _content_has_live_marker,
    _content_is_edit,
)

__all__ = [
    "MessageMixin",
    "_build_live_message_metadata",
    "_content_has_live_marker",
    "_content_is_edit",
]
