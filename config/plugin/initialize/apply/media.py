"""Plugin matrix_media configuration extraction and normalization."""

from ....defaults import (
    _DEFAULT_HTTP_TIMEOUT_SECONDS,
    _DEFAULT_MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES,
    _DEFAULT_QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY,
    _normalize_bool,
    _normalize_non_negative_int,
)


class PluginConfigInitializationMediaMixin:
    """Apply matrix_media settings from the config dictionary."""

    def _initialize_media_settings(self, config: dict) -> None:
        # 其他配置仍然允许配置
        media_obj = config.get("matrix_media")

        http_timeout_seconds = None
        media_cache_gc_days = None
        media_download_concurrency = None
        quoted_media_background_download_concurrency = None
        media_download_min_interval_ms = None
        media_download_breaker_fail_threshold = None
        media_download_breaker_cooldown_ms = None
        media_download_breaker_max_cooldown_ms = None
        media_cache_index_persist = None
        media_download_max_in_memory_bytes = None
        if isinstance(media_obj, dict):
            if isinstance(media_obj.get("http_timeout_seconds"), (int, float, str)):
                http_timeout_seconds = media_obj.get("http_timeout_seconds")
            if isinstance(media_obj.get("cache_gc_days"), (int, float, str)):
                media_cache_gc_days = media_obj.get("cache_gc_days")
            if isinstance(media_obj.get("download_concurrency"), (int, float, str)):
                media_download_concurrency = media_obj.get("download_concurrency")
            if isinstance(
                media_obj.get("quoted_background_download_concurrency"),
                (int, float, str),
            ):
                quoted_media_background_download_concurrency = media_obj.get(
                    "quoted_background_download_concurrency"
                )
            if isinstance(media_obj.get("download_min_interval_ms"), (int, float, str)):
                media_download_min_interval_ms = media_obj.get(
                    "download_min_interval_ms"
                )
            if isinstance(
                media_obj.get("download_breaker_fail_threshold"), (int, float, str)
            ):
                media_download_breaker_fail_threshold = media_obj.get(
                    "download_breaker_fail_threshold"
                )
            if isinstance(
                media_obj.get("download_breaker_cooldown_ms"), (int, float, str)
            ):
                media_download_breaker_cooldown_ms = media_obj.get(
                    "download_breaker_cooldown_ms"
                )
            if isinstance(
                media_obj.get("download_breaker_max_cooldown_ms"), (int, float, str)
            ):
                media_download_breaker_max_cooldown_ms = media_obj.get(
                    "download_breaker_max_cooldown_ms"
                )
            if isinstance(media_obj.get("cache_index_persist"), (bool, str)):
                media_cache_index_persist = media_obj.get("cache_index_persist")
            if isinstance(
                media_obj.get("download_max_in_memory_bytes"), (int, float, str)
            ):
                media_download_max_in_memory_bytes = media_obj.get(
                    "download_max_in_memory_bytes"
                )

        if http_timeout_seconds is None:
            http_timeout_seconds = config.get("matrix_http_timeout_seconds")
        if media_cache_gc_days is None:
            media_cache_gc_days = config.get("matrix_media_cache_gc_days")
        if media_download_concurrency is None:
            media_download_concurrency = config.get("matrix_media_download_concurrency")
        if quoted_media_background_download_concurrency is None:
            quoted_media_background_download_concurrency = config.get(
                "matrix_quoted_media_background_download_concurrency"
            )
        if media_download_min_interval_ms is None:
            media_download_min_interval_ms = config.get(
                "matrix_media_download_min_interval_ms"
            )
        if media_download_breaker_fail_threshold is None:
            media_download_breaker_fail_threshold = config.get(
                "matrix_media_download_breaker_fail_threshold"
            )
        if media_download_breaker_cooldown_ms is None:
            media_download_breaker_cooldown_ms = config.get(
                "matrix_media_download_breaker_cooldown_ms"
            )
        if media_download_breaker_max_cooldown_ms is None:
            media_download_breaker_max_cooldown_ms = config.get(
                "matrix_media_download_breaker_max_cooldown_ms"
            )
        if media_cache_index_persist is None:
            media_cache_index_persist = config.get("matrix_media_cache_index_persist")
        if media_download_max_in_memory_bytes is None:
            media_download_max_in_memory_bytes = config.get(
                "matrix_media_download_max_in_memory_bytes"
            )

        self._http_timeout_seconds = _normalize_non_negative_int(
            http_timeout_seconds,
            _DEFAULT_HTTP_TIMEOUT_SECONDS,
            min_value=5,
            config_key="matrix_media.http_timeout_seconds",
        )
        self._media_cache_gc_days = _normalize_non_negative_int(
            media_cache_gc_days,
            30,
            min_value=0,
            config_key="matrix_media.cache_gc_days",
        )
        self._media_download_concurrency = _normalize_non_negative_int(
            media_download_concurrency,
            4,
            min_value=1,
            config_key="matrix_media.download_concurrency",
        )
        self._quoted_media_background_download_concurrency = (
            _normalize_non_negative_int(
                quoted_media_background_download_concurrency,
                _DEFAULT_QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY,
                min_value=1,
                config_key="matrix_media.quoted_background_download_concurrency",
            )
        )
        self._media_download_min_interval_ms = _normalize_non_negative_int(
            media_download_min_interval_ms,
            0,
            min_value=0,
            config_key="matrix_media.download_min_interval_ms",
        )
        self._media_download_breaker_fail_threshold = _normalize_non_negative_int(
            media_download_breaker_fail_threshold,
            6,
            min_value=0,
            config_key="matrix_media.download_breaker_fail_threshold",
        )
        self._media_download_breaker_cooldown_ms = _normalize_non_negative_int(
            media_download_breaker_cooldown_ms,
            5000,
            min_value=0,
            config_key="matrix_media.download_breaker_cooldown_ms",
        )
        self._media_download_breaker_max_cooldown_ms = _normalize_non_negative_int(
            media_download_breaker_max_cooldown_ms,
            120000,
            min_value=0,
            config_key="matrix_media.download_breaker_max_cooldown_ms",
        )
        self._media_cache_index_persist = _normalize_bool(
            media_cache_index_persist, True
        )
        self._media_download_max_in_memory_bytes = _normalize_non_negative_int(
            media_download_max_in_memory_bytes,
            _DEFAULT_MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES,
            min_value=0,
            config_key="matrix_media.download_max_in_memory_bytes",
        )
