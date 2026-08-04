"""Media-cache directory resolution."""

from pathlib import Path

from astrbot.core.utils import astrbot_path

from ......config.plugin import get_plugin_config


class MatrixReceiverMediaCacheDirsMixin:
    """Resolve the media-cache working directory."""

    def _get_media_cache_dir(self) -> Path:
        """获取媒体文件缓存目录"""
        try:
            cache_dir = Path(get_plugin_config().media_cache_dir)
        except Exception:
            cache_dir = (
                Path(astrbot_path.get_astrbot_data_path()) / "temp" / "matrix_media"
            )

        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir
