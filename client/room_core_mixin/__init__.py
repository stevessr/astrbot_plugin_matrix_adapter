"""Layered core Matrix room operations."""

from .events import RoomEventSearchMixin
from .membership import RoomMembershipMixin
from .messages import RoomMessageHistoryMixin
from .state import RoomCoreStateMixin


class RoomCoreMixin(
    RoomMembershipMixin,
    RoomMessageHistoryMixin,
    RoomCoreStateMixin,
    RoomEventSearchMixin,
):
    """Core room-related methods for Matrix client."""

    pass


# Keep the composed class's method surface compatible with the former
# single-module implementation.  The implementations remain owned by their
# responsibility-specific mixins, while these aliases preserve direct class
# introspection for existing consumers.
RoomCoreMixin.join_room = RoomMembershipMixin.join_room
RoomCoreMixin.leave_room = RoomMembershipMixin.leave_room
RoomCoreMixin.get_room_members = RoomMembershipMixin.get_room_members
RoomCoreMixin.room_messages = RoomMessageHistoryMixin.room_messages
RoomCoreMixin.get_joined_rooms = RoomMessageHistoryMixin.get_joined_rooms
RoomCoreMixin.get_room_state = RoomCoreStateMixin.get_room_state
RoomCoreMixin.is_room_encrypted = RoomCoreStateMixin.is_room_encrypted
RoomCoreMixin.get_room_state_event = RoomCoreStateMixin.get_room_state_event
RoomCoreMixin.set_room_state_event = RoomCoreStateMixin.set_room_state_event
RoomCoreMixin.get_event = RoomEventSearchMixin.get_event
RoomCoreMixin.search = RoomEventSearchMixin.search


__all__ = [
    "RoomCoreMixin",
    "RoomMembershipMixin",
    "RoomMessageHistoryMixin",
    "RoomCoreStateMixin",
    "RoomEventSearchMixin",
]
