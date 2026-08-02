"""Layered Matrix sticker-pack synchronization package."""

from .models import StickerPackInfo
from .query import StickerPackQueryMixin
from .state import StickerSyncStateMixin
from .sync import StickerPackOperationsMixin


class StickerPackSyncer(
    StickerSyncStateMixin,
    StickerPackOperationsMixin,
    StickerPackQueryMixin,
):
    """
    Sticker 包同步器

    负责同步房间和用户级 sticker 包，并提供不下载的包查询能力。
    """

    pass


__all__ = [
    "StickerPackSyncer",
    "StickerPackInfo",
    "StickerSyncStateMixin",
    "StickerPackOperationsMixin",
    "StickerPackQueryMixin",
]
