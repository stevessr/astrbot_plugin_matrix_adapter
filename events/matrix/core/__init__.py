"""Composable Matrix platform event implementation."""

import time

from astrbot.api.event import AstrMessageEvent

from ....constants import (
    M_ROOM_MESSAGE,
    MATRIX_HTML_FORMAT,
    MSC4357_LIVE_MESSAGE_MARKER,
    MSGTYPE_NOTICE,
    MSGTYPE_TEXT,
    STREAMING_TYPING_REFRESH_SECONDS,
    STREAMING_TYPING_TIMEOUT_MS,
)
from ..stream import MatrixPlatformEventStreamMixin
from .actions import MatrixPlatformEventActionsMixin
from .send import MatrixPlatformEventSendMixin
from .state import MatrixPlatformEventStateMixin


class MatrixPlatformEvent(
    MatrixPlatformEventStreamMixin,
    MatrixPlatformEventStateMixin,
    MatrixPlatformEventSendMixin,
    MatrixPlatformEventActionsMixin,
    AstrMessageEvent,
):
    """Matrix platform event handler without a matrix-nio dependency."""

    pass


__all__ = [
    "MatrixPlatformEvent",
    "time",
    "MATRIX_HTML_FORMAT",
    "M_ROOM_MESSAGE",
    "MSC4357_LIVE_MESSAGE_MARKER",
    "MSGTYPE_NOTICE",
    "MSGTYPE_TEXT",
    "STREAMING_TYPING_REFRESH_SECONDS",
    "STREAMING_TYPING_TIMEOUT_MS",
]
