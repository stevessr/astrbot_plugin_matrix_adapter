"""Composable Matrix user room discovery and creation operations."""

from typing import Any

from astrbot.api import logger

from ...path_utils import quote_path_segment
from .creation import UserRoomCreationMixin
from .mutual import UserMutualRoomsMixin


class UserRoomMixin(UserMutualRoomsMixin, UserRoomCreationMixin):
    """Shared-room lookup and room-creation helpers."""

    pass


# Preserve direct methods exposed by the former rooms mixin.
for _mixin in (UserMutualRoomsMixin, UserRoomCreationMixin):
    for _method_name, _method in _mixin.__dict__.items():
        if callable(_method) and not _method_name.startswith("__"):
            setattr(UserRoomMixin, _method_name, _method)


__all__ = [
    "Any",
    "UserMutualRoomsMixin",
    "UserRoomCreationMixin",
    "UserRoomMixin",
    "logger",
    "quote_path_segment",
]
