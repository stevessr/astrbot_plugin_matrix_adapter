"""Sticker search and listing operations."""

from .list import StickerStorageListMixin
from .search import StickerStorageSearchMixin


class StickerStorageQueryMixin(
    StickerStorageSearchMixin,
    StickerStorageListMixin,
):
    """Filter stickers, packs, and available metadata."""


# Preserve direct method attributes expected by parent-package __dict__ lookups.
for _mixin in (
    StickerStorageSearchMixin,
    StickerStorageListMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(StickerStorageQueryMixin, _method_name, _method)


__all__ = [
    "StickerStorageListMixin",
    "StickerStorageQueryMixin",
    "StickerStorageSearchMixin",
]
