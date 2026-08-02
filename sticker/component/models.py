"""Sticker metadata models."""

from dataclasses import dataclass
from typing import Any


@dataclass
class StickerInfo:
    """Sticker 元信息"""

    mimetype: str = "image/png"
    width: int | None = None
    height: int | None = None
    size: int | None = None
    thumbnail_url: str | None = None
    thumbnail_info: dict[str, Any] | None = None


__all__ = ["StickerInfo"]
