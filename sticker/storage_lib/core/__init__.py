"""Composable core implementation for sticker storage."""

from .index import StickerStorageIndexMixin
from .items import StickerStorageItemsMixin
from .maintenance import StickerStorageMaintenanceMixin
from .query import StickerStorageQueryMixin


class StickerStorageCoreMixin(
    StickerStorageIndexMixin,
    StickerStorageItemsMixin,
    StickerStorageQueryMixin,
    StickerStorageMaintenanceMixin,
):
    """Combined sticker index, item, query, and maintenance behavior."""

    pass


__all__ = ["StickerStorageCoreMixin"]
