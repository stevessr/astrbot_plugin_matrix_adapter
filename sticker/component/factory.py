"""Sticker factory constructors."""

import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .sticker import Sticker

from .models import StickerInfo


class StickerFactoryMixin:
    """Construct stickers from common URL and payload formats."""

    @staticmethod
    def fromURL(url: str, body: str = "", **kwargs) -> "Sticker":
        """从 URL 创建 Sticker"""
        if (
            url.startswith("http://")
            or url.startswith("https://")
            or url.startswith("mxc://")
        ):
            from .sticker import Sticker

            return Sticker(body=body, url=url, **kwargs)
        raise ValueError("not a valid url")

    @staticmethod
    def fromFileSystem(path: str, body: str = "", **kwargs) -> "Sticker":
        """从本地文件系统创建 Sticker"""
        abs_path = os.path.abspath(path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"File not found: {abs_path}")
        from .sticker import Sticker

        return Sticker(
            body=body or Path(path).stem, url=f"file:///{abs_path}", **kwargs
        )

    @staticmethod
    def fromBase64(
        base64_data: str, body: str = "", mimetype: str = "image/png", **kwargs
    ) -> "Sticker":
        """从 base64 数据创建 Sticker"""
        info = StickerInfo(mimetype=mimetype)
        from .sticker import Sticker

        return Sticker(body=body, url=f"base64://{base64_data}", info=info, **kwargs)

    @staticmethod
    def fromMXC(mxc_url: str, body: str = "", **kwargs) -> "Sticker":
        """从 Matrix 媒体 URL 创建 Sticker"""
        if not mxc_url.startswith("mxc://"):
            raise ValueError("not a valid mxc:// URL")
        from .sticker import Sticker

        return Sticker(body=body, url=mxc_url, mxc_url=mxc_url, **kwargs)


__all__ = ["StickerFactoryMixin"]
