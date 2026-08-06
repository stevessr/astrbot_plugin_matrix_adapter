"""Extraction of nested matrix_media settings."""

from typing import Any


def _extract_media_block(media_obj: Any) -> dict[str, Any]:
    """从 matrix_media 嵌套对象中提取媒体设置原值。"""
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


__all__ = ["_extract_media_block"]
