"""Composable room-state operations for the Matrix HTTP client."""

from ..base import MatrixAPIError
from .configuration import RoomStateConfigurationMixin
from .inspection import RoomStateInspectionMixin
from .pins import RoomPinnedEventsMixin


class RoomStateMixin(
    RoomStateInspectionMixin,
    RoomStateConfigurationMixin,
    RoomPinnedEventsMixin,
):
    """Combined room inspection, configuration, and pinned-event behavior."""

    pass


__all__ = [
    "MatrixAPIError",
    "RoomPinnedEventsMixin",
    "RoomStateConfigurationMixin",
    "RoomStateInspectionMixin",
    "RoomStateMixin",
]
