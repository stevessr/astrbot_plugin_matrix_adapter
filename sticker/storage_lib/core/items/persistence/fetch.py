"""Sticker file-data acquisition."""

import anyio

from astrbot.api import logger

from .....component import Sticker


class StickerStoragePersistenceFetchMixin:
    """Obtain sticker bytes from file_data, mxc://, or a local path."""

    async def _fetch_sticker_bytes(
        self,
        sticker: Sticker,
        file_data: bytes | None,
        client=None,
    ) -> bytes:
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
        return bytes(file_data)


__all__ = ["StickerStoragePersistenceFetchMixin"]
