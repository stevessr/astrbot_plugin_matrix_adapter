"""Sticker file persistence and metadata creation orchestration."""

import time

import anyio

from astrbot.api import logger

from .....component import Sticker
from ....meta import StickerMeta
from .dimensions import StickerStoragePersistenceDimensionsMixin
from .fetch import StickerStoragePersistenceFetchMixin
from .update import StickerStoragePersistenceUpdateMixin


class StickerStoragePersistenceOrchestratorMixin(
    StickerStoragePersistenceUpdateMixin,
    StickerStoragePersistenceFetchMixin,
    StickerStoragePersistenceDimensionsMixin,
):
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
        meta = self._update_existing_sticker(sticker_id, pack_name, tags)
        if meta is not None:
            return meta

        # 确定缓存路径
        cache_path = self._generate_cache_path(
            sticker_id,
            sticker.info.mimetype,
            room_id=room_id,
            pack_name=pack_name or sticker.pack_name,
        )

        # 获取文件数据
        file_data = await self._fetch_sticker_bytes(sticker, file_data, client)

        # 保存文件
        await anyio.Path(cache_path).write_bytes(file_data)

        # 获取图片尺寸
        width, height = self._probe_image_dimensions(
            cache_path,
            sticker.info.width,
            sticker.info.height,
        )

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


__all__ = [
    "StickerStoragePersistenceDimensionsMixin",
    "StickerStoragePersistenceFetchMixin",
    "StickerStoragePersistenceOrchestratorMixin",
    "StickerStoragePersistenceUpdateMixin",
]
