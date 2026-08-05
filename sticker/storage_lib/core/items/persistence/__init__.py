"""Sticker file persistence and metadata creation."""

from .core import StickerStoragePersistenceOrchestratorMixin
from .dimensions import StickerStoragePersistenceDimensionsMixin
from .fetch import StickerStoragePersistenceFetchMixin
from .update import StickerStoragePersistenceUpdateMixin


class StickerStoragePersistenceMixin(StickerStoragePersistenceOrchestratorMixin):
    """Save sticker bytes and update storage metadata."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    StickerStoragePersistenceOrchestratorMixin,
    StickerStoragePersistenceUpdateMixin,
    StickerStoragePersistenceFetchMixin,
    StickerStoragePersistenceDimensionsMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if callable(_method) and not _method_name.startswith("__"):
            setattr(StickerStoragePersistenceMixin, _method_name, _method)


__all__ = [
    "StickerStoragePersistenceDimensionsMixin",
    "StickerStoragePersistenceFetchMixin",
    "StickerStoragePersistenceMixin",
    "StickerStoragePersistenceOrchestratorMixin",
    "StickerStoragePersistenceUpdateMixin",
]
