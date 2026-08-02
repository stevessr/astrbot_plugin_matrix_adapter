"""Configurable download flow-control policies."""

from .compat import get_plugin_config


class MediaDownloadFlowConfigMixin:
    """Resolve download concurrency, buffering, and breaker settings."""

    _MEDIA_DOWNLOAD_CONCURRENCY_DEFAULT = 4

    _MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES_DEFAULT = 32 * 1024 * 1024

    @staticmethod
    def _normalize_media_source_key(source_key: str | None) -> str:
        if isinstance(source_key, str):
            normalized = source_key.strip().lower()
            if normalized:
                return normalized
        return "__homeserver__"

    def _get_media_download_concurrency_limit(self) -> int:
        default_limit = self._MEDIA_DOWNLOAD_CONCURRENCY_DEFAULT
        try:
            configured_limit = int(get_plugin_config().media_download_concurrency)
        except Exception:
            return default_limit
        if configured_limit <= 0:
            return default_limit
        return min(configured_limit, 64)

    def _get_media_download_max_in_memory_bytes(self) -> int:
        default_limit = self._MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES_DEFAULT
        try:
            configured_limit = int(
                get_plugin_config().media_download_max_in_memory_bytes
            )
        except Exception:
            return default_limit
        if configured_limit <= 0:
            return 0
        return min(configured_limit, 1024 * 1024 * 1024)

    def _get_media_download_min_interval_seconds(self) -> float:
        try:
            interval_ms = int(get_plugin_config().media_download_min_interval_ms)
        except Exception:
            return 0.0
        if interval_ms <= 0:
            return 0.0
        return interval_ms / 1000.0

    def _get_media_download_breaker_fail_threshold(self) -> int:
        try:
            threshold = int(get_plugin_config().media_download_breaker_fail_threshold)
        except Exception:
            return 6
        return max(0, threshold)

    def _get_media_download_breaker_base_cooldown_seconds(self) -> float:
        try:
            cooldown_ms = int(get_plugin_config().media_download_breaker_cooldown_ms)
        except Exception:
            return 5.0
        if cooldown_ms <= 0:
            return 0.0
        return cooldown_ms / 1000.0

    def _get_media_download_breaker_max_cooldown_seconds(self) -> float:
        try:
            cooldown_ms = int(
                get_plugin_config().media_download_breaker_max_cooldown_ms
            )
        except Exception:
            return 120.0
        if cooldown_ms <= 0:
            return 0.0
        return cooldown_ms / 1000.0

    def _is_media_download_breaker_enabled(self) -> bool:
        if self._get_media_download_breaker_fail_threshold() <= 0:
            return False
        return self._get_media_download_breaker_base_cooldown_seconds() > 0
