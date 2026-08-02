"""Sticker synchronization data models."""

from dataclasses import dataclass


@dataclass
class StickerPackInfo:
    """Sticker 包信息"""

    pack_name: str
    display_name: str
    avatar_url: str | None
    sticker_count: int
    room_id: str | None  # 如果是房间 sticker 包
    is_user_pack: bool  # 是否是用户级别的包


__all__ = ["StickerPackInfo"]
