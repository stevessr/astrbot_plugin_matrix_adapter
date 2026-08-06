"""Sticker listing operations."""

from ...meta import StickerMeta


class StickerStorageListMixin:
    """List stickers and packs."""

    def list_stickers(
        self,
        pack_name: str | None = None,
        limit: int = 50,
        available_ids: set[str] | None = None,
    ) -> list[StickerMeta]:
        """
        列出所有 sticker

        Args:
            pack_name: 可选，按包名过滤
            limit: 返回数量限制

        Returns:
            StickerMeta 列表
        """
        results = []
        if available_ids is None and self.availability_store:
            available_ids = self.availability_store.get_ids()

        for sticker_id, meta in self._index.items():
            if available_ids is not None and sticker_id not in available_ids:
                continue
            if pack_name and meta.pack_name != pack_name:
                continue
            results.append(meta)
            if len(results) >= limit:
                break
        return results

    def list_packs(self) -> list[str]:
        """
        列出所有 sticker 包名称

        Returns:
            包名称列表
        """
        packs = set()
        available_ids = (
            self.availability_store.get_ids() if self.availability_store else None
        )
        for sticker_id, meta in self._index.items():
            if available_ids is not None and sticker_id not in available_ids:
                continue
            if meta.pack_name:
                packs.add(meta.pack_name)
        return sorted(packs)


__all__ = ["StickerStorageListMixin"]
