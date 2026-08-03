"""Sticker file persistence and metadata creation."""

import time

import anyio

from astrbot.api import logger

from ....component import Sticker
from ...meta import StickerMeta


class StickerStoragePersistenceMixin:
    """Save sticker bytes and update storage metadata."""

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
