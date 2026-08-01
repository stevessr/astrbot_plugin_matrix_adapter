"""Matrix platform event implementation."""

from .core import (
    M_ROOM_MESSAGE,
    MATRIX_HTML_FORMAT,
    MSC4357_LIVE_MESSAGE_MARKER,
    MSGTYPE_NOTICE,
    MSGTYPE_TEXT,
    STREAMING_TYPING_REFRESH_SECONDS,
    STREAMING_TYPING_TIMEOUT_MS,
    MatrixPlatformEvent,
)
from .stream import MatrixPlatformEventStreamMixin

__all__ = [
    "MatrixPlatformEvent",
    "MatrixPlatformEventStreamMixin",
    "MATRIX_HTML_FORMAT",
    "M_ROOM_MESSAGE",
    "MSC4357_LIVE_MESSAGE_MARKER",
    "MSGTYPE_NOTICE",
    "MSGTYPE_TEXT",
    "STREAMING_TYPING_REFRESH_SECONDS",
    "STREAMING_TYPING_TIMEOUT_MS",
]
