"""
Matrix 工具方法组件
"""

import asyncio
import io
from pathlib import Path
from urllib.parse import quote

from astrbot.api import logger

from ..constants import (
    DEFAULT_MAX_UPLOAD_SIZE_BYTES,
    IMAGE_MAX_DIMENSION,
    IMAGE_MIN_QUALITY,
    IMAGE_MIN_WIDTH,
    IMAGE_QUALITY_STEP,
    IMAGE_RESIZE_SCALE_FACTOR,
)
from .utils_lib import MatrixUtilsMixin



def parse_bool(value: object, default: bool = False) -> bool:
    """Consolidated boolean parsing helper."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on", "enable", "enabled"}:
        return True
    if normalized in {"0", "false", "no", "off", "disable", "disabled"}:
        return False
    return default


def mask_device_id(device_id: str | None) -> str:
    """统一的 device_id 脱敏显示函数。

    将 device_id 脱敏为 ``前 2 + *** + 后 2`` 的格式，
    用于日志输出。短于 4 字符的 ID 返回 ``***``。
    """
    if not isinstance(device_id, str) or not device_id:
        return "<empty>"
    normalized = device_id.strip()
    if len(normalized) <= 4:
        return "***"
    return f"{normalized[:2]}***{normalized[-2:]}"


def _extract_text_repr(value) -> str:
    """Extract a text representation from a Matrix event content value.

    Handles strings, dicts with body/text keys, and lists of such items.
    Used by event_types.py, beacon.py, location.py.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return str(value.get("body") or value.get("text") or "")
    if isinstance(value, list):
        for item in value:
            text = _extract_text_repr(item)
            if text:
                return text
    return ""


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

        # 打开图片
        with PILImage.open(io.BytesIO(image_data)) as img:
            # 转换为 RGB 模式（处理 RGBA、P 等模式）
            if img.mode in ("RGBA", "P", "LA"):
                # 保留 alpha 通道的图片转换为带白色背景的 RGB
                background = PILImage.new("RGB", img.size, (255, 255, 255))
                if img.mode == "P":
                    img = img.convert("RGBA")
                background.paste(
                    img, mask=img.split()[-1] if img.mode == "RGBA" else None
                )
                img = background
            elif img.mode != "RGB":
                img = img.convert("RGB")

            # 第一步：缩小尺寸（如果太大）
            width, height = img.size
            if width > IMAGE_MAX_DIMENSION or height > IMAGE_MAX_DIMENSION:
                ratio = min(IMAGE_MAX_DIMENSION / width, IMAGE_MAX_DIMENSION / height)
                new_width = int(width * ratio)
                new_height = int(height * ratio)
                img = img.resize((new_width, new_height), PILImage.Resampling.LANCZOS)
                logger.debug(
                    f"图片尺寸从 {width}x{height} 缩小到 {new_width}x{new_height}"
                )

            # 第二步：逐步降低质量直到满足大小要求
            quality = 85  # 起始质量
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

            # 如果最低质量仍然超过限制，进一步缩小尺寸
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


class MatrixUtils(MatrixUtilsMixin):
    """
    Matrix 工具类（静态工具类）。

    The protocol-specific operations live in ``utils_lib`` mixins; this
    compatibility class keeps the historical import path and constructor
    contract.
    """

    def __init__(self):
        raise TypeError(
            "MatrixUtils is a static utility class and should not be instantiated"
        )
