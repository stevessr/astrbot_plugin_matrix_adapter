"""Inbound message callback operations."""

from .convert import _convert_event
from .core import message_callback
from .dispatch import _dispatch_message
from .reaction import _handle_reaction_event
from .stalk import _record_stalk_archive


class MatrixAdapterMessageCallbackMixin:
    """Process converted inbound Matrix messages."""

    message_callback = message_callback


__all__ = [
    "_convert_event",
    "_dispatch_message",
    "_handle_reaction_event",
    "_record_stalk_archive",
    "message_callback",
]
