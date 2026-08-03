"""Composable Matrix message event processing operations."""

from typing import TYPE_CHECKING

from astrbot.api import logger

from ....client.event_types import parse_event
from ....constants import (
    M_ROOM_ENCRYPTED,
    M_ROOM_MESSAGE,
    TIMESTAMP_BUFFER_MS_1000,
)
from .dispatch import MatrixEventProcessorMessagesOperationsMixin


class MatrixEventProcessorMessagesMixin(MatrixEventProcessorMessagesOperationsMixin):
    """Mixin for message event processing."""

    pass


# Preserve direct method attributes exposed by the former mixin.
MatrixEventProcessorMessagesMixin._process_message_event = (
    MatrixEventProcessorMessagesOperationsMixin.__dict__["_process_message_event"]
)


__all__ = [
    "M_ROOM_ENCRYPTED",
    "M_ROOM_MESSAGE",
    "TIMESTAMP_BUFFER_MS_1000",
    "TYPE_CHECKING",
    "MatrixEventProcessorMessagesMixin",
    "MatrixEventProcessorMessagesOperationsMixin",
    "logger",
    "parse_event",
]
