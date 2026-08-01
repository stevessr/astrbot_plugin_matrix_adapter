"""Composable sticker-storage implementation."""

from pathlib import Path

from ..availability import StickerAvailabilityStore
from .core import StickerStorageCoreMixin
from .meta import StickerMeta, _get_sticker_storage_path, _sanitize_segment


class StickerStorage(StickerStorageCoreMixin):
    """Sticker cache/index manager with a stable legacy constructor."""

    def __init__(
        self,
        storage_path: str | None = None,
        availability_store: StickerAvailabilityStore | None = None,
    ):
        self.storage_dir = (
            Path(storage_path) if storage_path else _get_sticker_storage_path()
        )
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir = self.storage_dir / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.storage_dir / "sticker_index.json"
        self.availability_store = availability_store
        self._index: dict[str, StickerMeta] = {}
        self._load_index()


__all__ = [
    "StickerStorage",
    "StickerMeta",
    "_get_sticker_storage_path",
    "_sanitize_segment",
]
