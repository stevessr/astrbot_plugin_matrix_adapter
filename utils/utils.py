"""
Matrix 工具方法组件
"""

import io
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


class MatrixUtils:
    """
    Matrix 工具类（静态工具类）

    提供 Matrix 协议相关的实用工具方法。

    注意：此类仅包含静态方法，不应被实例化。
    所有方法都是无状态的转换和处理工具。
    """

    def __init__(self):
        """禁止实例化此工具类"""
        raise TypeError(
            "MatrixUtils is a static utility class and should not be instantiated"
        )

    @staticmethod
    def _parse_mxc_url(mxc_url: str) -> tuple[str, str] | None:
        normalized = str(mxc_url or "").strip()
        if not normalized.startswith("mxc://"):
            return None
        parts = normalized[6:].split("/", 1)
        if len(parts) != 2:
            return None
        server_name = parts[0].strip()
        media_id = parts[1].split("?", 1)[0].split("#", 1)[0].strip().lstrip("/")
        if not server_name or not media_id:
            return None
        return server_name, media_id

    @staticmethod
    def mxc_to_http(mxc_url: str, homeserver: str) -> str:
        parsed = MatrixUtils._parse_mxc_url(mxc_url)
        if parsed is None:
            return mxc_url
        base_url = str(homeserver or "").strip().rstrip("/")
        if not base_url:
            return mxc_url
        server_name, media_id = parsed
        return (
            f"{base_url}/_matrix/client/v1/media/download/"
            f"{quote(server_name, safe='')}/{quote(media_id, safe='')}"
        )

    @staticmethod
    def create_reply_fallback(
        original_body: str, original_sender: str, original_event_id: str, room_id: str
    ) -> str:
        """
        生成 Matrix 回复引用 (fallback)
        格式参考：https://spec.matrix.org/latest/client-server-api/#fallbacks-for-rich-replies
        <mx-reply>
          <blockquote>
            <a href="https://matrix.to/#/!somewhere:example.org/$event:example.org">In reply to</a>
            <a href="https://matrix.to/#/@alice:example.org">@alice:example.org</a>
            <br />
            Message content
          </blockquote>
        </mx-reply>
        """
        # 防止 original_body 为空或其他类型
        if not original_body:
            original_body = ""

        # 简单截断过长内容，避免引用过大
        if len(original_body) > 200:
            original_body = original_body[:200] + "..."

        # 转义 HTML 特殊字符，避免注入
        import html

        safe_body = html.escape(original_body).replace("\n", "<br />")

        return (
            f"<mx-reply>"
            f"<blockquote>"
            f'<a href="https://matrix.to/#/{room_id}/{original_event_id}">In reply to</a> '
            f'<a href="https://matrix.to/#/{original_sender}">{original_sender}</a>'
            f"<br />{safe_body}"
            f"</blockquote>"
            f"</mx-reply>"
        )

    @staticmethod
    def strip_reply_fallback(body: str) -> str:
        """
        去除 Matrix 回复的 fallback 内容 (引用文本)
        通常格式为：
        > <@user:server> message

        或者
        > <@user:server>
        > message
        """
        if not body:
            return ""
        # 1. 匹配标准 fallback 格式：以 > <@user:id> 开头，可能跨越多行
        # 匹配模式：
        # ^> <.*?>.*?\n\n
        # 或者简单的多行 > 开头的块

        # 常见的 fallback 结构是：
        # > <@sender:server> original message...
        # > ... continued ...
        #
        # new message

        # 我们尝试移除所有连续的以 > 开头的行，以及随后的空行

        lines = body.split("\n")
        # 统计开头的 fallback 行数
        fallback_line_count = 0

        for line in lines:
            if line.startswith(">") or (fallback_line_count > 0 and line.strip() == ""):
                fallback_line_count += 1
            else:
                break

        if fallback_line_count > 0:
            # 移除 fallback 行
            return "\n".join(lines[fallback_line_count:]).lstrip()

        return body

    @staticmethod
    def iter_platform_instances(context) -> list:
        """获取平台实例列表（兼容 get_insts / platform_insts）。"""
        platform_manager = getattr(context, "platform_manager", None)
        if platform_manager is None:
            return []

        get_insts = getattr(platform_manager, "get_insts", None)
        if callable(get_insts):
            try:
                platforms = get_insts()
                if isinstance(platforms, list):
                    return platforms
                return list(platforms)
            except Exception as e:
                logger.debug(f"通过 get_insts 获取平台实例失败：{e}")

        platforms = getattr(platform_manager, "platform_insts", None)
        if isinstance(platforms, list):
            return platforms
        return []

    @staticmethod
    def get_matrix_platform(context, platform_id: str = ""):
        """获取 Matrix 平台实例，优先匹配 platform_id，失败则回退第一个。"""
        target_platform_id = str(platform_id or "")
        fallback_platform = None

        try:
            for platform in MatrixUtils.iter_platform_instances(context):
                try:
                    meta = platform.meta()
                except Exception:
                    continue

                meta_name = str(getattr(meta, "name", "") or "").strip().lower()
                if meta_name != "matrix":
                    continue

                if fallback_platform is None:
                    fallback_platform = platform

                meta_id = str(getattr(meta, "id", "") or "")
                if target_platform_id and meta_id == target_platform_id:
                    return platform
        except Exception as e:
            logger.debug(f"获取 Matrix 平台实例失败：{e}")

        return fallback_platform

    @staticmethod
    def get_matrix_client(context, platform_id: str = ""):
        """获取 Matrix 客户端实例。"""
        platform = MatrixUtils.get_matrix_platform(context, platform_id)
        if platform is None:
            return None
        return getattr(platform, "client", None)

    @staticmethod
    def get_matrix_e2ee_manager(context, platform_id: str = ""):
        """获取 Matrix E2EE 管理器实例。"""
        platform = MatrixUtils.get_matrix_platform(context, platform_id)
        if platform is None:
            return None
        return getattr(platform, "e2ee_manager", None)
