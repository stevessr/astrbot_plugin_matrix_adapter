"""Matrix sticker event serialization helpers."""

import hashlib
from typing import TYPE_CHECKING, Any

from .models import StickerInfo

if TYPE_CHECKING:
    from .sticker import Sticker


class StickerMatrixMixin:
    """Serialize and parse Matrix ``m.sticker`` event content."""

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


__all__ = ["StickerMatrixMixin"]
