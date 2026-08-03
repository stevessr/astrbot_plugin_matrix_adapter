"""Composable Matrix room lifecycle and hierarchy operations."""

from typing import Any

from ..path_utils import quote_path_segment
from .hierarchy import RoomHierarchyMixin
from .lifecycle import RoomLifecycleMixin


class RoomManagementMixin(
    RoomLifecycleMixin,
    RoomHierarchyMixin,
):
    """Room management methods for Matrix client"""

    pass


# Preserve direct method attributes exposed by the former mixin.
RoomManagementMixin.forget_room = RoomLifecycleMixin.__dict__["forget_room"]
RoomManagementMixin.upgrade_room = RoomLifecycleMixin.__dict__["upgrade_room"]
RoomManagementMixin.knock_room = RoomLifecycleMixin.__dict__["knock_room"]
RoomManagementMixin.accept_knock = RoomLifecycleMixin.__dict__["accept_knock"]
RoomManagementMixin.reject_knock = RoomLifecycleMixin.__dict__["reject_knock"]
RoomManagementMixin.get_room_hierarchy = RoomHierarchyMixin.__dict__[
    "get_room_hierarchy"
]


__all__ = ["Any", "RoomManagementMixin", "quote_path_segment"]
