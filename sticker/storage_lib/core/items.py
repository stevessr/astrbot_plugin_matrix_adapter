"""Sticker file and item lifecycle operations."""

import os
import time
from pathlib import Path

import anyio

from astrbot.api import logger

from ...component import Sticker, StickerInfo
from ..meta import StickerMeta, _sanitize_segment


class StickerStorageItemsMixin:
    """Save, materialize, and update individual stickers."""

    def _generate_cache_path(
        self,
        sticker_id: str,
        mimetype: str,
        room_id: str | None = None,
        pack_name: str | None = None,
    ) -> Path:
        """生成缓存文件路径"""
        # 根据 mimetype 确定扩展名
        ext_map = {
            "image/png": ".png",
            "image/jpeg": ".jpg",
            "image/gif": ".gif",
            "image/webp": ".webp",
        }
        ext = ext_map.get(mimetype, ".png")
        room_seg = f"room_{_sanitize_segment(room_id)}" if room_id else "user"
        pack_seg = _sanitize_segment(pack_name or "default")
        cache_dir = self.cache_dir / room_seg / pack_seg
        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir / f"{sticker_id}{ext}"

    async def save_sticker(
        self,
        sticker: Sticker,
        file_data: bytes | None = None,
        client=None,
        pack_name: str | None = None,
        room_id: str | None = None,
        tags: list[str] | None = None,
    ) -> StickerMeta:
        """
        保存 sticker 到本地存储

        Args:
            sticker: Sticker 对象
            file_data: 可选，sticker 文件数据
            client: 可选，Matrix HTTP client（用于从 mxc:// 下载）
            pack_name: 可选，sticker 包名称
            tags: 可选，标签列表

        Returns:
            StickerMeta: 保存后的元数据
        """
        # 生成 sticker ID
        sticker_id = sticker.generate_sticker_id()

        # 如果已存在，更新使用信息
        if sticker_id in self._index:
            meta = self._index[sticker_id]
            meta.last_used = time.time()
            meta.use_count += 1
            if pack_name:
                meta.pack_name = pack_name
            if tags:
                meta.tags = tags
            self.save_index()
            return meta

        # 确定缓存路径
        cache_path = self._generate_cache_path(
            sticker_id,
            sticker.info.mimetype,
            room_id=room_id,
            pack_name=pack_name or sticker.pack_name,
        )

        # 获取文件数据
        if file_data is None:
            if sticker.url.startswith("mxc://") and client:
                # 从 Matrix 媒体服务器下载
                try:
                    file_data = await client.download_file(
                        sticker.url, allow_thumbnail_fallback=True
                    )
                except Exception as e:
                    logger.error(f"下载 sticker 失败：{e}")
                    raise
            elif not sticker.url.startswith("mxc://"):
                # 从本地或 HTTP URL 获取
                try:
                    file_path = await sticker.convert_to_file_path()
                    file_data = await anyio.Path(file_path).read_bytes()
                except Exception as e:
                    logger.error(f"获取 sticker 文件失败：{e}")
                    raise
            else:
                raise ValueError("需要提供 file_data 或 client 来下载 mxc:// URL")

        # 保存文件
        await anyio.Path(cache_path).write_bytes(bytes(file_data))

        # 获取图片尺寸
        width, height = sticker.info.width, sticker.info.height
        if width is None or height is None:
            try:
                from PIL import Image as PILImage

                with PILImage.open(cache_path) as img:
                    width, height = img.size
            except Exception:
                pass

        # 创建元数据
        now = time.time()
        meta = StickerMeta(
            sticker_id=sticker_id,
            body=sticker.body,
            mxc_url=sticker.mxc_url or sticker.url,
            local_path=str(cache_path),
            mimetype=sticker.info.mimetype,
            width=width,
            height=height,
            pack_name=pack_name or sticker.pack_name,
            room_id=room_id,
            created_at=now,
            last_used=now,
            use_count=1,
            tags=tags,
        )

        # 更新索引
        self._index[sticker_id] = meta
        self.save_index()

        logger.info(f"保存 sticker: {sticker_id}")
        return meta

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
