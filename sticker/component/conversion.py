"""Sticker file, URL, and Base64 conversion helpers."""

import base64
import os
import uuid
from pathlib import Path

from astrbot.core.utils.astrbot_path import get_astrbot_data_path
from astrbot.core.utils.io import download_image_by_url


class StickerConversionMixin:
    """Convert sticker payloads to local files and Base64 data."""

    def _get_cache_dir(self) -> Path:
        """获取 sticker 缓存目录"""
        cache_dir = Path(get_astrbot_data_path()) / "temp" / "matrix_sticker"
        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir

    async def convert_to_file_path(self) -> str:
        """
        将 sticker 统一转换为本地文件路径

        Returns:
            str: 本地文件的绝对路径
        """
        url = self.url
        if not url:
            raise ValueError("No valid URL provided")

        if url.startswith("file:///"):
            return url[8:]

        if url.startswith("http://") or url.startswith("https://"):
            # 下载到缓存目录
            image_file_path = await download_image_by_url(url)
            return os.path.abspath(image_file_path)

        if url.startswith("base64://"):
            # 解码 base64 并保存
            bs64_data = url.removeprefix("base64://")
            image_bytes = base64.b64decode(bs64_data)
            cache_dir = self._get_cache_dir()
            file_path = cache_dir / f"sticker_{uuid.uuid4().hex}.png"
            with open(file_path, "wb") as f:
                f.write(image_bytes)
            return str(file_path)

        if url.startswith("mxc://"):
            # MXC URL 需要通过 Matrix client 下载
            # 这里返回 None，让调用方处理
            raise ValueError(
                "MXC URL requires Matrix client to download. "
                "Use StickerStorage.download_sticker() instead."
            )

        # 尝试作为本地路径
        if os.path.exists(url):
            return os.path.abspath(url)

        raise ValueError(f"not a valid sticker URL: {url}")

    async def convert_to_base64(self) -> str:
        """
        将 sticker 转换为 base64 编码

        Returns:
            str: base64 编码的数据（不含前缀）
        """
        url = self.url
        if not url:
            raise ValueError("No valid URL provided")

        if url.startswith("base64://"):
            return url.removeprefix("base64://")

        # 其他情况先转换为文件路径，再读取
        try:
            file_path = await self.convert_to_file_path()
            with open(file_path, "rb") as f:
                return base64.b64encode(f.read()).decode()
        except ValueError as e:
            if "MXC URL" in str(e):
                raise
            raise


__all__ = ["StickerConversionMixin"]
