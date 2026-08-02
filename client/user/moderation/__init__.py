"""Composable Matrix user membership and permission operations."""

from typing import Any

from astrbot.api import logger

from ...path_utils import quote_path_segment
from .members import UserMembersMixin
from .membership import UserMembershipMixin
from .power import UserPowerLevelsMixin


class UserModerationMixin(
    UserMembershipMixin,
    UserPowerLevelsMixin,
    UserMembersMixin,
):
    """Invitation, moderation, power-level, and member helpers."""

    pass


# Preserve direct method attributes exposed by the former mixin.
UserModerationMixin.invite_user = UserMembershipMixin.__dict__["invite_user"]
UserModerationMixin.kick_user = UserMembershipMixin.__dict__["kick_user"]
UserModerationMixin.ban_user = UserMembershipMixin.__dict__["ban_user"]
UserModerationMixin.unban_user = UserMembershipMixin.__dict__["unban_user"]
UserModerationMixin.get_power_levels = UserPowerLevelsMixin.__dict__["get_power_levels"]
UserModerationMixin.set_power_levels = UserPowerLevelsMixin.__dict__["set_power_levels"]
UserModerationMixin.set_user_power_level = UserPowerLevelsMixin.__dict__[
    "set_user_power_level"
]
UserModerationMixin.promote_to_moderator = UserPowerLevelsMixin.__dict__[
    "promote_to_moderator"
]
UserModerationMixin.promote_to_admin = UserPowerLevelsMixin.__dict__["promote_to_admin"]
UserModerationMixin.demote_user = UserPowerLevelsMixin.__dict__["demote_user"]
UserModerationMixin.get_room_member = UserMembersMixin.__dict__["get_room_member"]
UserModerationMixin.get_room_admins = UserMembersMixin.__dict__["get_room_admins"]
UserModerationMixin.get_room_moderators = UserMembersMixin.__dict__[
    "get_room_moderators"
]


__all__ = ["Any", "UserModerationMixin", "logger", "quote_path_segment"]
