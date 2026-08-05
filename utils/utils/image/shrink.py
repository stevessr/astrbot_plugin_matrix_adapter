"""Progressive shrink loop for oversized compressed images."""

import io

from astrbot.api import logger

from ....constants import (
    IMAGE_MIN_QUALITY,
    IMAGE_MIN_WIDTH,
    IMAGE_RESIZE_SCALE_FACTOR,
)


def _shrink_to_fit(img, compressed_data: bytes, max_size: int, PILImage) -> bytes:
    current_width, current_height = img.size
    while len(compressed_data) > max_size and current_width > IMAGE_MIN_WIDTH:
        current_width = int(current_width * IMAGE_RESIZE_SCALE_FACTOR)
        current_height = int(current_height * IMAGE_RESIZE_SCALE_FACTOR)
        img = img.resize((current_width, current_height), PILImage.Resampling.LANCZOS)

        buffer = io.BytesIO()
        img.save(buffer, format="JPEG", quality=IMAGE_MIN_QUALITY, optimize=True)
        compressed_data = buffer.getvalue()

        logger.debug(
            f"进一步缩小图片到 {current_width}x{current_height}，"
            f"大小：{len(compressed_data) / 1024:.1f}KB"
        )

    return compressed_data
