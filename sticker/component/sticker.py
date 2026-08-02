"""Composed Matrix Sticker message component."""

from dataclasses import dataclass, field

from .conversion import StickerConversionMixin
from .factory import StickerFactoryMixin
from .models import StickerInfo
from .serialization import StickerMatrixMixin


@dataclass
class Sticker(
    StickerFactoryMixin,
    StickerConversionMixin,
    StickerMatrixMixin,
):
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


__all__ = ["Sticker"]
