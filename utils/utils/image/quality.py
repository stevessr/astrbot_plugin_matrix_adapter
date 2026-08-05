"""JPEG quality-step compression loop."""

import io

from astrbot.api import logger

from ....constants import IMAGE_MIN_QUALITY, IMAGE_QUALITY_STEP


def _compress_with_quality(img, max_size: int, original_size: int, PILImage):
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
            return compressed_data, True

        quality -= IMAGE_QUALITY_STEP

    return compressed_data, False
