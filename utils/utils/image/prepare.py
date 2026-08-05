"""Image mode flattening and dimension limiting."""

from astrbot.api import logger

from ....constants import IMAGE_MAX_DIMENSION


def _flatten_to_rgb(img, PILImage):
    if img.mode in ("RGBA", "P", "LA"):
        background = PILImage.new("RGB", img.size, (255, 255, 255))
        if img.mode == "P":
            img = img.convert("RGBA")
        background.paste(img, mask=img.split()[-1] if img.mode == "RGBA" else None)
        img = background
    elif img.mode != "RGB":
        img = img.convert("RGB")
    return img


def _resize_oversized_image(img, PILImage):
    width, height = img.size
    if width > IMAGE_MAX_DIMENSION or height > IMAGE_MAX_DIMENSION:
        ratio = min(IMAGE_MAX_DIMENSION / width, IMAGE_MAX_DIMENSION / height)
        new_width = int(width * ratio)
        new_height = int(height * ratio)
        img = img.resize((new_width, new_height), PILImage.Resampling.LANCZOS)
        logger.debug(f"图片尺寸从 {width}x{height} 缩小到 {new_width}x{new_height}")
    return img
