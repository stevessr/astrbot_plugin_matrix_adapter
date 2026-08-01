"""Sticker cache maintenance and statistics."""

import os
import time
from typing import Any

from astrbot.api import logger


class StickerStorageMaintenanceMixin:
    """Delete, clear, and summarize sticker cache contents."""

    def delete_sticker(self, sticker_id: str) -> bool:
        """
        删除 sticker

        Args:
            sticker_id: sticker ID

        Returns:
            是否成功删除
        """
        if sticker_id not in self._index:
            return False

        meta = self._index[sticker_id]

        # 删除缓存文件
        if meta.local_path and os.path.exists(meta.local_path):
            try:
                os.remove(meta.local_path)
            except Exception as e:
                logger.warning(f"删除 sticker 缓存文件失败：{e}")

        # 从索引中移除
        del self._index[sticker_id]
        self.save_index()

        logger.info(f"删除 sticker: {sticker_id}")
        return True

    def clear_cache(self, older_than_days: int | None = None):
        """
        清理缓存

        Args:
            older_than_days: 可选，只清理超过指定天数的缓存
        """
        now = time.time()
        to_delete = []

        for sticker_id, meta in self._index.items():
            if older_than_days:
                age_days = (now - meta.last_used) / 86400
                if age_days < older_than_days:
                    continue
            to_delete.append(sticker_id)

        for sticker_id in to_delete:
            self.delete_sticker(sticker_id)

        logger.info(f"清理了 {len(to_delete)} 个 sticker 缓存")

    def get_stats(self) -> dict[str, Any]:
        """
        获取存储统计信息

        Returns:
            统计信息字典
        """
        total_count = len(self._index)
        total_size = 0
        packs = set()

        for meta in self._index.values():
            if meta.local_path and os.path.exists(meta.local_path):
                total_size += os.path.getsize(meta.local_path)
            if meta.pack_name:
                packs.add(meta.pack_name)

        return {
            "total_count": total_count,
            "total_size_mb": round(total_size / 1024 / 1024, 2),
            "pack_count": len(packs),
            "packs": sorted(packs),
        }
