"""Extraction of matrix_media settings from the config dictionary."""

from typing import Any

from .nested import _extract_media_block

# 顶层兼容键：matrix_media 未设置时回退读取。
_FALLBACK_CONFIG_KEYS = {
    "http_timeout_seconds": "matrix_http_timeout_seconds",
    "media_cache_gc_days": "matrix_media_cache_gc_days",
    "media_download_concurrency": "matrix_media_download_concurrency",
    "quoted_media_background_download_concurrency": (
        "matrix_quoted_media_background_download_concurrency"
    ),
    "media_download_min_interval_ms": "matrix_media_download_min_interval_ms",
    "media_download_breaker_fail_threshold": (
        "matrix_media_download_breaker_fail_threshold"
    ),
    "media_download_breaker_cooldown_ms": "matrix_media_download_breaker_cooldown_ms",
    "media_download_breaker_max_cooldown_ms": (
        "matrix_media_download_breaker_max_cooldown_ms"
    ),
    "media_cache_index_persist": "matrix_media_cache_index_persist",
    "media_download_max_in_memory_bytes": "matrix_media_download_max_in_memory_bytes",
}


def _extract_media_settings(config: dict) -> dict[str, Any]:
    """从嵌套 matrix_media 与顶层兼容键中提取媒体设置原值。"""
    # 其他配置仍然允许配置
    values = _extract_media_block(config.get("matrix_media"))

    for field, config_key in _FALLBACK_CONFIG_KEYS.items():
        if values[field] is None:
            values[field] = config.get(config_key)

    return values


__all__ = ["_extract_media_settings"]
