"""Sticker metadata update for existing entries."""

import time

from ....meta import StickerMeta


class StickerStoragePersistenceUpdateMixin:
    """Update usage information for an already-indexed sticker."""

    def _update_existing_sticker(
        self,
        sticker_id: str,
        pack_name: str | None,
        tags: list[str] | None,
    ) -> StickerMeta | None:
        if sticker_id not in self._index:
            return None
        meta = self._index[sticker_id]
        meta.last_used = time.time()
        meta.use_count += 1
        if pack_name:
            meta.pack_name = pack_name
        if tags:
            meta.tags = tags
        self.save_index()
        return meta


__all__ = ["StickerStoragePersistenceUpdateMixin"]
