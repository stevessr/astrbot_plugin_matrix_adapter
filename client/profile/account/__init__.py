"""Composable Matrix account-data, profile, and room state operations."""

from typing import Any

from astrbot.api import logger

from ....constants import M_MARKED_UNREAD, MSC2867_MARKED_UNREAD
from ...path_utils import quote_path_segment
from .account_data import ProfileAccountDataMixin
from .profile import ProfileUserMixin
from .rooms import ProfileRoomStateMixin


class ProfileAccountMixin(
    ProfileAccountDataMixin, ProfileUserMixin, ProfileRoomStateMixin
):
    """Account data and user profile methods for Matrix client"""

    pass


# Preserve direct method attributes exposed by the former mixin.
ProfileAccountMixin.get_global_account_data = ProfileAccountDataMixin.__dict__[
    "get_global_account_data"
]
ProfileAccountMixin.set_global_account_data = ProfileAccountDataMixin.__dict__[
    "set_global_account_data"
]
ProfileAccountMixin.get_room_account_data = ProfileAccountDataMixin.__dict__[
    "get_room_account_data"
]
ProfileAccountMixin.set_room_account_data = ProfileAccountDataMixin.__dict__[
    "set_room_account_data"
]
ProfileAccountMixin.set_display_name = ProfileUserMixin.__dict__["set_display_name"]
ProfileAccountMixin.get_display_name = ProfileUserMixin.__dict__["get_display_name"]
ProfileAccountMixin.get_avatar_url = ProfileUserMixin.__dict__["get_avatar_url"]
ProfileAccountMixin.set_avatar_url = ProfileUserMixin.__dict__["set_avatar_url"]
ProfileAccountMixin.get_user_room = ProfileRoomStateMixin.__dict__["get_user_room"]
ProfileAccountMixin.set_room_marked_unread = ProfileRoomStateMixin.__dict__[
    "set_room_marked_unread"
]
ProfileAccountMixin.get_room_marked_unread = ProfileRoomStateMixin.__dict__[
    "get_room_marked_unread"
]


__all__ = [
    "Any",
    "M_MARKED_UNREAD",
    "MSC2867_MARKED_UNREAD",
    "ProfileAccountMixin",
    "logger",
    "quote_path_segment",
]
