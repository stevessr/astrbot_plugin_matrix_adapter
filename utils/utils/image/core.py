"""Image compression helpers for Matrix uploads."""

import io

from astrbot.api import logger

from ....constants import DEFAULT_MAX_UPLOAD_SIZE_BYTES
from .prepare import _flatten_to_rgb, _resize_oversized_image
from .quality import _compress_with_quality
from .shrink import _shrink_to_fit


def compress_image_if_needed(
    image_data: bytes,
    content_type: str,
    max_size: int = DEFAULT_MAX_UPLOAD_SIZE_BYTES,
) -> tuple[bytes, str, bool]:
    """
    如果图片大小超过限制，尝试压缩图片。

    Args:
        image_data: 原始图片数据
        content_type: 原始 MIME 类型
        max_size: 最大文件大小（字节）

    Returns:
        (压缩后的数据，新的 MIME 类型，是否进行了压缩)
    """
    if len(image_data) <= max_size:
        return image_data, content_type, False

    try:
        from PIL import Image as PILImage

        original_size = len(image_data)
        logger.info(
            f"图片大小 ({original_size / 1024 / 1024:.2f}MB) 超过限制 "
            f"({max_size / 1024 / 1024:.2f}MB)，尝试压缩"
        )

        with PILImage.open(io.BytesIO(image_data)) as img:
            img = _flatten_to_rgb(img, PILImage)

            img = _resize_oversized_image(img, PILImage)

            compressed_data, compressed = _compress_with_quality(
                img, max_size, original_size, PILImage
            )
            if compressed:
                return compressed_data, "image/jpeg", True

            compressed_data = _shrink_to_fit(img, compressed_data, max_size, PILImage)

            if len(compressed_data) <= max_size:
                logger.info(
                    f"图片压缩成功：{original_size / 1024:.1f}KB -> "
                    f"{len(compressed_data) / 1024:.1f}KB"
                )
                return compressed_data, "image/jpeg", True
            else:
                logger.warning(
                    f"图片压缩后仍然超过限制 ({len(compressed_data) / 1024:.1f}KB)，"
                    "将使用压缩后的版本尝试上传"
                )
                return compressed_data, "image/jpeg", True

    except ImportError:
        logger.warning("PIL 未安装，无法压缩图片")
        return image_data, content_type, False
    except Exception as e:
        logger.error(f"压缩图片时出错：{e}")
        return image_data, content_type, False


__all__ = ["compress_image_if_needed"]
