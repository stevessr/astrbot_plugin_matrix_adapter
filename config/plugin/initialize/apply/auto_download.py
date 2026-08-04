"""Plugin matrix_auto_download configuration extraction and normalization."""

from ....defaults import _normalize_bool, _normalize_non_negative_int


class PluginConfigInitializationAutoDownloadMixin:
    """Apply matrix_auto_download media settings from the config dictionary."""

    def _initialize_auto_download_settings(self, config: dict) -> None:
        auto_download_obj = config.get("matrix_auto_download")

        media_auto_download_max_bytes = None
        media_auto_download_image = None
        media_auto_download_video = None
        media_auto_download_audio = None
        media_auto_download_file = None
        media_auto_download_sticker = None
        if isinstance(auto_download_obj, dict):
            if isinstance(auto_download_obj.get("max_bytes"), (int, float, str)):
                media_auto_download_max_bytes = auto_download_obj.get("max_bytes")
            if isinstance(auto_download_obj.get("image"), (bool, str)):
                media_auto_download_image = auto_download_obj.get("image")
            if isinstance(auto_download_obj.get("video"), (bool, str)):
                media_auto_download_video = auto_download_obj.get("video")
            if isinstance(auto_download_obj.get("audio"), (bool, str)):
                media_auto_download_audio = auto_download_obj.get("audio")
            if isinstance(auto_download_obj.get("file"), (bool, str)):
                media_auto_download_file = auto_download_obj.get("file")
            if isinstance(auto_download_obj.get("sticker"), (bool, str)):
                media_auto_download_sticker = auto_download_obj.get("sticker")

        if media_auto_download_max_bytes is None:
            media_auto_download_max_bytes = config.get(
                "matrix_media_auto_download_max_bytes"
            )
        if media_auto_download_image is None:
            media_auto_download_image = config.get("matrix_media_auto_download_image")
        if media_auto_download_video is None:
            media_auto_download_video = config.get("matrix_media_auto_download_video")
        if media_auto_download_audio is None:
            media_auto_download_audio = config.get("matrix_media_auto_download_audio")
        if media_auto_download_file is None:
            media_auto_download_file = config.get("matrix_media_auto_download_file")
        if media_auto_download_sticker is None:
            media_auto_download_sticker = config.get(
                "matrix_media_auto_download_sticker"
            )

        self._media_auto_download_max_bytes = _normalize_non_negative_int(
            media_auto_download_max_bytes,
            0,
            min_value=0,
            config_key="matrix_auto_download.max_bytes",
        )
        self._media_auto_download_image = _normalize_bool(
            media_auto_download_image, True
        )
        self._media_auto_download_video = _normalize_bool(
            media_auto_download_video, True
        )
        self._media_auto_download_audio = _normalize_bool(
            media_auto_download_audio, True
        )
        self._media_auto_download_file = _normalize_bool(media_auto_download_file, True)
        self._media_auto_download_sticker = _normalize_bool(
            media_auto_download_sticker, True
        )
