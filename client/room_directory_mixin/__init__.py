"""Composable Matrix room directory and alias operations."""

from typing import Any

from ..path_utils import quote_path_segment
from .aliases import RoomAliasMixin
from .public import RoomPublicDirectoryMixin


class RoomDirectoryMixin(
    RoomAliasMixin,
    RoomPublicDirectoryMixin,
):
    """Room directory and aliases methods for Matrix client"""

    pass


# Preserve direct method attributes exposed by the former mixin.
RoomDirectoryMixin.create_room_alias = RoomAliasMixin.__dict__["create_room_alias"]
RoomDirectoryMixin.delete_room_alias = RoomAliasMixin.__dict__["delete_room_alias"]
RoomDirectoryMixin.get_room_alias = RoomAliasMixin.__dict__["get_room_alias"]
RoomDirectoryMixin.list_public_rooms = RoomPublicDirectoryMixin.__dict__[
    "list_public_rooms"
]
RoomDirectoryMixin.get_room_aliases = RoomAliasMixin.__dict__["get_room_aliases"]
RoomDirectoryMixin.get_room_visibility = RoomPublicDirectoryMixin.__dict__[
    "get_room_visibility"
]
RoomDirectoryMixin.set_room_visibility = RoomPublicDirectoryMixin.__dict__[
    "set_room_visibility"
]


__all__ = ["Any", "RoomDirectoryMixin", "quote_path_segment"]
