"""Composable sticker-pack synchronization operations."""

from typing import Any

from astrbot.api import logger

from ...component import Sticker, StickerInfo
from .pack import StickerPackSyncMixin
from .room import StickerRoomSyncMixin
from .user import StickerUserSyncMixin


class StickerPackOperationsMixin(
    StickerRoomSyncMixin,
    StickerUserSyncMixin,
    StickerPackSyncMixin,
):
    """Aggregate room, user, and single-pack synchronization operations."""

    pass


# Preserve direct methods exposed by the former sync mixin.
for _mixin in (StickerRoomSyncMixin, StickerUserSyncMixin, StickerPackSyncMixin):
    for _method_name, _method in _mixin.__dict__.items():
        if callable(_method) and not _method_name.startswith("__"):
            setattr(StickerPackOperationsMixin, _method_name, _method)


__all__ = [
    "Any",
    "Sticker",
    "StickerInfo",
    "StickerPackOperationsMixin",
    "StickerPackSyncMixin",
    "StickerRoomSyncMixin",
    "StickerUserSyncMixin",
    "logger",
]
