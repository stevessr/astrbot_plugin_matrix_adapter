"""Composable Matrix to-device event processing operations."""

from astrbot.api import logger

from ....constants import (
    M_FORWARDED_ROOM_KEY,
    M_ROOM_ENCRYPTED,
    M_ROOM_KEY,
    M_ROOM_KEY_REQUEST,
    M_ROOM_KEY_WITHHELD,
    MEGOLM_ALGO,
)
from .dispatch import MatrixEventProcessorToDeviceOperationsMixin


class MatrixEventProcessorToDeviceMixin(MatrixEventProcessorToDeviceOperationsMixin):
    """Handle encrypted room-key, verification, and secret events."""

    pass


# Preserve direct method attributes exposed by the former mixin.
MatrixEventProcessorToDeviceMixin.process_to_device_events = (
    MatrixEventProcessorToDeviceOperationsMixin.__dict__["process_to_device_events"]
)


__all__ = [
    "M_FORWARDED_ROOM_KEY",
    "M_ROOM_ENCRYPTED",
    "M_ROOM_KEY",
    "M_ROOM_KEY_REQUEST",
    "M_ROOM_KEY_WITHHELD",
    "MEGOLM_ALGO",
    "MatrixEventProcessorToDeviceMixin",
    "MatrixEventProcessorToDeviceOperationsMixin",
    "logger",
]
