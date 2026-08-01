"""Compatibility exports for the split sticker storage implementation."""

from .storage_lib import (
    StickerMeta,
    StickerStorage,
    _get_sticker_storage_path,
    _sanitize_segment,
)

__all__ = [
    "StickerStorage",
    "StickerMeta",
    "_get_sticker_storage_path",
    "_sanitize_segment",
]
