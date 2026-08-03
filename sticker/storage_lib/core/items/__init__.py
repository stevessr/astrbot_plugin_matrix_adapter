"""Composable sticker item lifecycle operations."""

import os
import time
from pathlib import Path

import anyio

from astrbot.api import logger

from ....component import Sticker, StickerInfo
from ...meta import StickerMeta, _sanitize_segment
from .paths import StickerStoragePathsMixin
from .persistence import StickerStoragePersistenceMixin
from .retrieval import StickerStorageRetrievalMixin


class StickerStorageItemsMixin(
    StickerStoragePathsMixin,
    StickerStoragePersistenceMixin,
    StickerStorageRetrievalMixin,
):
    """Save, materialize, and update individual stickers."""

    pass


for _mixin in (
    StickerStoragePathsMixin,
    StickerStoragePersistenceMixin,
    StickerStorageRetrievalMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if callable(_method) and not _method_name.startswith("__"):
            setattr(StickerStorageItemsMixin, _method_name, _method)


__all__ = [
    "Path",
    "Sticker",
    "StickerInfo",
    "StickerMeta",
    "StickerStorageItemsMixin",
    "_sanitize_segment",
    "anyio",
    "logger",
    "os",
    "time",
]
