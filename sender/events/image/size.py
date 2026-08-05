"""Image dimension detection."""

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
