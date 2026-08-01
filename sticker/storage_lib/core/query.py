"""Sticker search and listing operations."""

from ...component import Sticker
from ..meta import StickerMeta


class StickerStorageQueryMixin:
    """Filter stickers, packs, and available metadata."""

    def find_stickers(
        self,
        query: str | None = None,
        pack_name: str | None = None,
        tags: list[str] | None = None,
        limit: int = 20,
        available_ids: set[str] | None = None,
    ) -> list[Sticker]:
        """
        搜索 sticker

        Args:
            query: 搜索关键词（匹配 body）
            pack_name: 按包名过滤
            tags: 按标签过滤
            limit: 返回数量限制

        Returns:
            匹配的 Sticker 列表
        """
        results = []

        if available_ids is None and self.availability_store:
            available_ids = self.availability_store.get_ids()

        for sticker_id, meta in self._index.items():
            if available_ids is not None and sticker_id not in available_ids:
                continue
            # 应用过滤条件
            if pack_name and meta.pack_name != pack_name:
                continue

            if tags and meta.tags:
                if not any(tag in meta.tags for tag in tags):
                    continue

            if query:
                query_lower = query.lower()
                if (
                    query_lower not in meta.body.lower()
                    and query_lower not in (meta.pack_name or "").lower()
                ):
                    continue

            # 创建 Sticker 对象
            sticker = self.get_sticker(sticker_id, update_usage=False)
            if sticker:
                results.append(sticker)

            if len(results) >= limit:
                break

        return results

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
