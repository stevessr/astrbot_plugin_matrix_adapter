"""Composable room invitation and common state-event operations."""

from typing import Any

from ....constants import (
    M_ROOM_AVATAR,
    M_ROOM_CANONICAL_ALIAS,
    M_ROOM_GUEST_ACCESS,
    M_ROOM_HISTORY_VISIBILITY,
    M_ROOM_JOIN_RULES,
    M_ROOM_NAME,
    M_ROOM_TOPIC,
)
from ...path_utils import quote_path_segment
from .events import RoomStateEventsMixin
from .membership import RoomInvitationMixin


class RoomStateConfigurationMixin(
    RoomInvitationMixin,
    RoomStateEventsMixin,
):
    """Third-party invitations and common room state settings."""

    pass


# Preserve direct method attributes exposed by the former mixin.
RoomStateConfigurationMixin.invite_3pid = RoomInvitationMixin.__dict__["invite_3pid"]
RoomStateConfigurationMixin.set_room_name = RoomStateEventsMixin.__dict__[
    "set_room_name"
]
RoomStateConfigurationMixin.set_room_topic = RoomStateEventsMixin.__dict__[
    "set_room_topic"
]
RoomStateConfigurationMixin.set_room_avatar = RoomStateEventsMixin.__dict__[
    "set_room_avatar"
]
RoomStateConfigurationMixin.set_room_join_rules = RoomStateEventsMixin.__dict__[
    "set_room_join_rules"
]
RoomStateConfigurationMixin.set_room_history_visibility = RoomStateEventsMixin.__dict__[
    "set_room_history_visibility"
]
RoomStateConfigurationMixin.set_room_guest_access = RoomStateEventsMixin.__dict__[
    "set_room_guest_access"
]
RoomStateConfigurationMixin.set_room_canonical_alias = RoomStateEventsMixin.__dict__[
    "set_room_canonical_alias"
]


__all__ = [
    "Any",
    "M_ROOM_AVATAR",
    "M_ROOM_CANONICAL_ALIAS",
    "M_ROOM_GUEST_ACCESS",
    "M_ROOM_HISTORY_VISIBILITY",
    "M_ROOM_JOIN_RULES",
    "M_ROOM_NAME",
    "M_ROOM_TOPIC",
    "RoomStateConfigurationMixin",
    "quote_path_segment",
]
