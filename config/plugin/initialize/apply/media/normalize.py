"""Normalization of extracted matrix_media settings."""

from typing import Any

from .....defaults import (
    _DEFAULT_HTTP_TIMEOUT_SECONDS,
    _DEFAULT_MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES,
    _DEFAULT_QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY,
    _normalize_bool,
    _normalize_non_negative_int,
)


class PluginConfigInitializationMediaNormalizeMixin:
    """Normalize extracted media values onto instance attributes."""

    def _apply_media_settings(self, values: dict[str, Any]) -> None:
        self._http_timeout_seconds = _normalize_non_negative_int(
            values["http_timeout_seconds"],
            _DEFAULT_HTTP_TIMEOUT_SECONDS,
            min_value=5,
            config_key="matrix_media.http_timeout_seconds",
        )
        self._media_cache_gc_days = _normalize_non_negative_int(
            values["media_cache_gc_days"],
            30,
            min_value=0,
            config_key="matrix_media.cache_gc_days",
        )
        self._media_download_concurrency = _normalize_non_negative_int(
            values["media_download_concurrency"],
            4,
            min_value=1,
            config_key="matrix_media.download_concurrency",
        )
        self._quoted_media_background_download_concurrency = (
            _normalize_non_negative_int(
                values["quoted_media_background_download_concurrency"],
                _DEFAULT_QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY,
                min_value=1,
                config_key="matrix_media.quoted_background_download_concurrency",
            )
        )
        self._media_download_min_interval_ms = _normalize_non_negative_int(
            values["media_download_min_interval_ms"],
            0,
            min_value=0,
            config_key="matrix_media.download_min_interval_ms",
        )
        self._media_download_breaker_fail_threshold = _normalize_non_negative_int(
            values["media_download_breaker_fail_threshold"],
            6,
            min_value=0,
            config_key="matrix_media.download_breaker_fail_threshold",
        )
        self._media_download_breaker_cooldown_ms = _normalize_non_negative_int(
            values["media_download_breaker_cooldown_ms"],
            5000,
            min_value=0,
            config_key="matrix_media.download_breaker_cooldown_ms",
        )
        self._media_download_breaker_max_cooldown_ms = _normalize_non_negative_int(
            values["media_download_breaker_max_cooldown_ms"],
            120000,
            min_value=0,
            config_key="matrix_media.download_breaker_max_cooldown_ms",
        )
        self._media_cache_index_persist = _normalize_bool(
            values["media_cache_index_persist"], True
        )
        self._media_download_max_in_memory_bytes = _normalize_non_negative_int(
            values["media_download_max_in_memory_bytes"],
            _DEFAULT_MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES,
            min_value=0,
            config_key="matrix_media.download_max_in_memory_bytes",
        )
