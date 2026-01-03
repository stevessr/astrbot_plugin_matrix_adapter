"""
Matrix Sticker 消息组件

提供类似 Image 的 Sticker 组件，用于 Matrix sticker 的发送和接收
"""

import base64
import hashlib
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from astrbot.core.utils.astrbot_path import get_astrbot_data_path
from astrbot.core.utils.io import download_image_by_url


@dataclass
class StickerInfo:
    """Sticker 元信息"""

    mimetype: str = "image/png"
    width: int | None = None
    height: int | None = None
    size: int | None = None
    thumbnail_url: str | None = None
    thumbnail_info: dict[str, Any] | None = None


@dataclass
class Sticker:
    """
    Matrix Sticker 消息组件

    与 Image 类似，但发送时使用 m.sticker 事件类型而非 m.room.message

    Attributes:
        body: sticker 的描述文本（alt text）
        url: sticker 文件的 URL 或本地路径
        info: sticker 的元信息
        mxc_url: Matrix 媒体服务器上的 mxc:// URL（发送后设置）
        sticker_id: sticker 的唯一标识符（用于存储和检索）
        pack_name: sticker 所属的包名称
    """

    body: str = ""
    url: str = ""  # 可以是本地路径、http URL 或 mxc:// URL
    info: StickerInfo = field(default_factory=StickerInfo)
    mxc_url: str | None = None
    sticker_id: str | None = None
    pack_name: str | None = None

    # 组件类型标识
    type: str = "Sticker"

    @staticmethod
    def fromURL(url: str, body: str = "", **kwargs) -> "Sticker":
        """从 URL 创建 Sticker"""
        if (
            url.startswith("http://")
            or url.startswith("https://")
            or url.startswith("mxc://")
        ):
            return Sticker(body=body, url=url, **kwargs)
        raise ValueError("not a valid url")

    @staticmethod
    def fromFileSystem(path: str, body: str = "", **kwargs) -> "Sticker":
        """从本地文件系统创建 Sticker"""
        abs_path = os.path.abspath(path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"File not found: {abs_path}")
        return Sticker(
            body=body or Path(path).stem, url=f"file:///{abs_path}", **kwargs
        )

    @staticmethod
    def fromBase64(
        base64_data: str, body: str = "", mimetype: str = "image/png", **kwargs
    ) -> "Sticker":
        """从 base64 数据创建 Sticker"""
        info = StickerInfo(mimetype=mimetype)
        return Sticker(body=body, url=f"base64://{base64_data}", info=info, **kwargs)

    @staticmethod
    def fromMXC(mxc_url: str, body: str = "", **kwargs) -> "Sticker":
        """从 Matrix 媒体 URL 创建 Sticker"""
        if not mxc_url.startswith("mxc://"):
            raise ValueError("not a valid mxc:// URL")
        return Sticker(body=body, url=mxc_url, mxc_url=mxc_url, **kwargs)

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

    def generate_sticker_id(self) -> str:
        """
        生成 sticker 的唯一标识符

        基于 URL 或内容生成 hash
        """
        if self.sticker_id:
            return self.sticker_id

        # 使用 URL 生成 hash
        content = self.url or self.body
        self.sticker_id = hashlib.md5(content.encode()).hexdigest()[:16]
        return self.sticker_id

    def to_matrix_content(self, mxc_url: str | None = None) -> dict[str, Any]:
        """
        转换为 Matrix sticker 事件的 content 格式

        Args:
            mxc_url: 可选，Matrix 媒体服务器上的 URL

        Returns:
            dict: Matrix m.sticker 事件的 content
        """
        content: dict[str, Any] = {
            "body": self.body or "sticker",
            "url": mxc_url or self.mxc_url or self.url,
        }

        # 添加 info 信息
        info_dict: dict[str, Any] = {"mimetype": self.info.mimetype}
        if self.info.width:
            info_dict["w"] = self.info.width
        if self.info.height:
            info_dict["h"] = self.info.height
        if self.info.size:
            info_dict["size"] = self.info.size
        if self.info.thumbnail_url:
            info_dict["thumbnail_url"] = self.info.thumbnail_url
        if self.info.thumbnail_info:
            info_dict["thumbnail_info"] = self.info.thumbnail_info

        content["info"] = info_dict

        return content

    @classmethod
    def from_matrix_event(cls, event_content: dict[str, Any]) -> "Sticker":
        """
        从 Matrix 事件内容创建 Sticker 对象

        Args:
            event_content: Matrix m.sticker 事件的 content

        Returns:
            Sticker: 解析后的 Sticker 对象
        """
        info_data = event_content.get("info", {})
        info = StickerInfo(
            mimetype=info_data.get("mimetype", "image/png"),
            width=info_data.get("w"),
            height=info_data.get("h"),
            size=info_data.get("size"),
            thumbnail_url=info_data.get("thumbnail_url"),
            thumbnail_info=info_data.get("thumbnail_info"),
        )

        mxc_url = event_content.get("url", "")

        return cls(
            body=event_content.get("body", ""),
            url=mxc_url,
            info=info,
            mxc_url=mxc_url if mxc_url.startswith("mxc://") else None,
        )

    def __repr__(self) -> str:
        return (
            f"Sticker(body={self.body!r}, url={self.url[:50]}..., id={self.sticker_id})"
        )
