"""Image compression helpers for Matrix uploads."""

import io

from astrbot.api import logger

from ...constants import (
    DEFAULT_MAX_UPLOAD_SIZE_BYTES,
    IMAGE_MAX_DIMENSION,
    IMAGE_MIN_QUALITY,
    IMAGE_MIN_WIDTH,
    IMAGE_QUALITY_STEP,
    IMAGE_RESIZE_SCALE_FACTOR,
)


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
            if img.mode in ("RGBA", "P", "LA"):
                background = PILImage.new("RGB", img.size, (255, 255, 255))
                if img.mode == "P":
                    img = img.convert("RGBA")
                background.paste(
                    img, mask=img.split()[-1] if img.mode == "RGBA" else None
                )
                img = background
            elif img.mode != "RGB":
                img = img.convert("RGB")

            width, height = img.size
            if width > IMAGE_MAX_DIMENSION or height > IMAGE_MAX_DIMENSION:
                ratio = min(IMAGE_MAX_DIMENSION / width, IMAGE_MAX_DIMENSION / height)
                new_width = int(width * ratio)
                new_height = int(height * ratio)
                img = img.resize((new_width, new_height), PILImage.Resampling.LANCZOS)
                logger.debug(
                    f"图片尺寸从 {width}x{height} 缩小到 {new_width}x{new_height}"
                )

            quality = 85
            compressed_data = b""

            while quality >= IMAGE_MIN_QUALITY:
                buffer = io.BytesIO()
                img.save(buffer, format="JPEG", quality=quality, optimize=True)
                compressed_data = buffer.getvalue()

                if len(compressed_data) <= max_size:
                    logger.info(
                        f"图片压缩成功：{original_size / 1024:.1f}KB -> "
                        f"{len(compressed_data) / 1024:.1f}KB (质量：{quality})"
                    )
                    return compressed_data, "image/jpeg", True

                quality -= IMAGE_QUALITY_STEP

            current_width, current_height = img.size
            while len(compressed_data) > max_size and current_width > IMAGE_MIN_WIDTH:
                current_width = int(current_width * IMAGE_RESIZE_SCALE_FACTOR)
                current_height = int(current_height * IMAGE_RESIZE_SCALE_FACTOR)
                img = img.resize(
                    (current_width, current_height), PILImage.Resampling.LANCZOS
                )

                buffer = io.BytesIO()
                img.save(
                    buffer, format="JPEG", quality=IMAGE_MIN_QUALITY, optimize=True
                )
                compressed_data = buffer.getvalue()

                logger.debug(
                    f"进一步缩小图片到 {current_width}x{current_height}，"
                    f"大小：{len(compressed_data) / 1024:.1f}KB"
                )

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
