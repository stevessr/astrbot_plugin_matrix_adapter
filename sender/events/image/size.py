"""Image dimension and animation detection."""

import io

from astrbot.api import logger

try:
    from PIL import Image as PILImage
except Exception:
    PILImage = None


def _get_image_dimensions_from_path(image_path):
    if PILImage is None:
        return None, None
    try:
        with PILImage.open(image_path) as img:
            return img.size
    except Exception as e:
        logger.debug(f"无法获取图片尺寸：{e}")
        return None, None


def _get_image_dimensions_from_data(image_data):
    if PILImage is None:
        return None, None
    try:
        with PILImage.open(io.BytesIO(image_data)) as img:
            return img.size
    except Exception as e:
        logger.debug(f"无法获取压缩后图片尺寸：{e}")
        return None, None


def _is_image_animated_from_path(image_path) -> bool | None:
    """Return animation state, or ``None`` when it cannot be determined."""
    if PILImage is None:
        return None
    try:
        with PILImage.open(image_path) as img:
            return bool(getattr(img, "is_animated", False))
    except Exception as e:
        logger.debug(f"无法检测图片动画状态：{e}")
        return None


def _is_image_animated_from_data(image_data) -> bool | None:
    """Return animation state for in-memory media, or ``None`` if unknown."""
    if PILImage is None:
        return None
    try:
        with PILImage.open(io.BytesIO(image_data)) as img:
            return bool(getattr(img, "is_animated", False))
    except Exception as e:
        logger.debug(f"无法检测压缩后图片动画状态：{e}")
        return None
