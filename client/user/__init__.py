"""Composable user-management mixins for the Matrix HTTP client."""

from .directory import UserDirectoryMixin
from .ignore import UserIgnoreMixin
from .moderation import UserModerationMixin
from .rooms import UserRoomMixin


class UserMixin(
    UserDirectoryMixin,
    UserModerationMixin,
    UserIgnoreMixin,
    UserRoomMixin,
):
    """Combined user directory, moderation, ignore, and room behavior."""

    pass


__all__ = [
    "UserDirectoryMixin",
    "UserIgnoreMixin",
    "UserMixin",
    "UserModerationMixin",
    "UserRoomMixin",
]
