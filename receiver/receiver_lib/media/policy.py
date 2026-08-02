"""Media auto-download policy and metadata helpers."""

from pathlib import Path

from ....config.plugin import get_plugin_config
from ....constants import (
    MSGTYPE_AUDIO,
    MSGTYPE_FILE,
    MSGTYPE_IMAGE,
    MSGTYPE_STICKER,
    MSGTYPE_VIDEO,
)


class MatrixReceiverMediaPolicyMixin:
    """Resolve media download policy, size limits, and image detection."""

    def _should_auto_download_media(self, msgtype: str) -> bool:
        """检查是否应该自动下载该类型的媒体文件"""
        if msgtype not in {
            MSGTYPE_IMAGE,
            MSGTYPE_STICKER,
            MSGTYPE_VIDEO,
            MSGTYPE_AUDIO,
            MSGTYPE_FILE,
        }:
            return False
        try:
            return get_plugin_config().is_media_auto_download_enabled(msgtype)
        except Exception:
            return True

    @staticmethod
    def _normalize_media_size(size_value) -> int | None:
        if isinstance(size_value, bool) or size_value is None:
            return None
        try:
            size = int(size_value)
        except (TypeError, ValueError):
            return None
        return size if size >= 0 else None

    def _extract_media_size(self, content: dict | None) -> int | None:
        if not isinstance(content, dict):
            return None
        info = content.get("info")
        if not isinstance(info, dict):
            return None
        return self._normalize_media_size(info.get("size"))

    def _get_media_auto_download_max_bytes(self) -> int:
        try:
            configured = int(get_plugin_config().media_auto_download_max_bytes)
        except Exception:
            return 0
        return max(0, configured)

    def _get_quoted_media_background_download_concurrency(self) -> int:
        try:
            configured = int(
                get_plugin_config().quoted_media_background_download_concurrency
            )
        except Exception:
            configured = self._QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY_DEFAULT
        if configured <= 0:
            configured = self._QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY_DEFAULT
        return min(configured, 32)

    def _is_media_over_auto_download_limit(self, size_bytes: int | None) -> bool:
        if size_bytes is None:
            return False
        max_bytes = self._get_media_auto_download_max_bytes()
        return max_bytes > 0 and size_bytes > max_bytes

    def _is_image_media(
        self, filename: str | None = None, mimetype: str | None = None
    ) -> bool:
        if mimetype:
            normalized = mimetype.lower().split(";")[0].strip()
            if normalized.startswith("image/"):
                return True
        if filename:
            return Path(filename).suffix.lower() in self._IMAGE_EXTENSIONS
        return False
