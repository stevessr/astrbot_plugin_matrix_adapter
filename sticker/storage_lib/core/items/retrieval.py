"""Sticker materialization and usage tracking."""

import os
import time

from ....component import Sticker, StickerInfo
from ...meta import StickerMeta


class StickerStorageRetrievalMixin:
    """Build stickers from metadata and update usage."""

    def _build_sticker_from_meta(self, sticker_id: str, meta: StickerMeta) -> Sticker:
        """从元数据构建 Sticker 对象，不修改使用计数。"""
        info = StickerInfo(
            mimetype=meta.mimetype,
            width=meta.width,
            height=meta.height,
        )

        has_mxc = meta.mxc_url and meta.mxc_url.startswith("mxc://")
        has_local = meta.local_path and os.path.exists(meta.local_path)

        if has_mxc:
            url = meta.mxc_url
        elif has_local:
            url = f"file:///{meta.local_path}"
        else:
            url = meta.mxc_url or ""

        return Sticker(
            body=meta.body,
            url=url,
            info=info,
            mxc_url=meta.mxc_url if has_mxc else None,
            sticker_id=sticker_id,
            pack_name=meta.pack_name,
        )

    def get_sticker(self, sticker_id: str, update_usage: bool = True) -> Sticker | None:
        """
        根据 ID 获取 sticker

        Args:
            sticker_id: sticker ID
            update_usage: 是否更新使用计数与最近使用时间

        Returns:
            Sticker 对象，如果不存在返回 None
        """
        if sticker_id not in self._index:
            return None

        meta = self._index[sticker_id]

        if update_usage:
            meta.last_used = time.time()
            meta.use_count += 1
            self.save_index()

        return self._build_sticker_from_meta(sticker_id, meta)

    def touch_sticker_usage(self, sticker_id: str) -> bool:
        """仅更新使用计数，不构建 Sticker 对象。"""
        meta = self._index.get(sticker_id)
        if meta is None:
            return False
        meta.last_used = time.time()
        meta.use_count += 1
        self.save_index()
        return True
