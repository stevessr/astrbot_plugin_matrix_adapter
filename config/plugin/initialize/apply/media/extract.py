"""Extraction of matrix_media settings from the config dictionary."""

from typing import Any


def _extract_media_settings(config: dict) -> dict[str, Any]:
    """从嵌套 matrix_media 与顶层兼容键中提取媒体设置原值。"""
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
            media_download_min_interval_ms = media_obj.get("download_min_interval_ms")
        if isinstance(
            media_obj.get("download_breaker_fail_threshold"), (int, float, str)
        ):
            media_download_breaker_fail_threshold = media_obj.get(
                "download_breaker_fail_threshold"
            )
        if isinstance(media_obj.get("download_breaker_cooldown_ms"), (int, float, str)):
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
        if isinstance(media_obj.get("download_max_in_memory_bytes"), (int, float, str)):
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

    return {
        "http_timeout_seconds": http_timeout_seconds,
        "media_cache_gc_days": media_cache_gc_days,
        "media_download_concurrency": media_download_concurrency,
        "quoted_media_background_download_concurrency": (
            quoted_media_background_download_concurrency
        ),
        "media_download_min_interval_ms": media_download_min_interval_ms,
        "media_download_breaker_fail_threshold": media_download_breaker_fail_threshold,
        "media_download_breaker_cooldown_ms": media_download_breaker_cooldown_ms,
        "media_download_breaker_max_cooldown_ms": media_download_breaker_max_cooldown_ms,
        "media_cache_index_persist": media_cache_index_persist,
        "media_download_max_in_memory_bytes": media_download_max_in_memory_bytes,
    }
