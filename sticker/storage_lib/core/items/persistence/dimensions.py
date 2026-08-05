"""Sticker image-dimension probing."""


class StickerStoragePersistenceDimensionsMixin:
    """Probe image dimensions when the sticker info omits them."""

    def _probe_image_dimensions(self, cache_path, width, height):
        if width is None or height is None:
            try:
                from PIL import Image as PILImage

                with PILImage.open(cache_path) as img:
                    width, height = img.size
            except Exception:
                pass
        return width, height


__all__ = ["StickerStoragePersistenceDimensionsMixin"]
