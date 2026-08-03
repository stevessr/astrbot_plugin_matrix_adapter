"""Sticker cache path generation."""

from pathlib import Path

from ...meta import _sanitize_segment


class StickerStoragePathsMixin:
    """Build deterministic sticker cache paths."""

    def _generate_cache_path(
        self,
        sticker_id: str,
        mimetype: str,
        room_id: str | None = None,
        pack_name: str | None = None,
    ) -> Path:
        """生成缓存文件路径"""
        # 根据 mimetype 确定扩展名
        ext_map = {
            "image/png": ".png",
            "image/jpeg": ".jpg",
            "image/gif": ".gif",
            "image/webp": ".webp",
        }
        ext = ext_map.get(mimetype, ".png")
        room_seg = f"room_{_sanitize_segment(room_id)}" if room_id else "user"
        pack_seg = _sanitize_segment(pack_name or "default")
        cache_dir = self.cache_dir / room_seg / pack_seg
        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir / f"{sticker_id}{ext}"
