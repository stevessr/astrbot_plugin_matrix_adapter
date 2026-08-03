"""Composable Matrix live-message streaming helpers."""

import html
import time

from astrbot.api import logger
from astrbot.api.event import MessageChain

from .....constants import (
    M_ROOM_MESSAGE,
    MATRIX_HTML_FORMAT,
    MSC4357_LIVE_MESSAGE_MARKER,
    MSGTYPE_NOTICE,
    MSGTYPE_TEXT,
)
from .....sender.event_send.crypto import (
    edit_message_encrypted,
    edit_message_plain,
    send_message_encrypted,
    send_message_plain,
)
from .....utils.markdown_utils import markdown_to_html
from ... import core as _matrix_event_module
from .relations import MatrixPlatformEventMessagesRelationsMixin
from .sending import MatrixPlatformEventMessagesSendingMixin


class MatrixPlatformEventMessagesMixin(
    MatrixPlatformEventMessagesRelationsMixin,
    MatrixPlatformEventMessagesSendingMixin,
):
    """Send live Matrix messages and preserve thread relationships."""

    pass


# Preserve direct methods exposed by the former messages mixin.
for _mixin in (
    MatrixPlatformEventMessagesRelationsMixin,
    MatrixPlatformEventMessagesSendingMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixPlatformEventMessagesMixin, _method_name, _method)


__all__ = [
    "M_ROOM_MESSAGE",
    "MATRIX_HTML_FORMAT",
    "MSC4357_LIVE_MESSAGE_MARKER",
    "MSGTYPE_NOTICE",
    "MSGTYPE_TEXT",
    "MatrixPlatformEventMessagesMixin",
    "MatrixPlatformEventMessagesRelationsMixin",
    "MatrixPlatformEventMessagesSendingMixin",
    "MessageChain",
    "_matrix_event_module",
    "edit_message_encrypted",
    "edit_message_plain",
    "html",
    "logger",
    "markdown_to_html",
    "send_message_encrypted",
    "send_message_plain",
    "time",
]
