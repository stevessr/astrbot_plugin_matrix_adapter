"""Composable concurrency, rate-limit, and breaker controls for downloads."""

import asyncio
import time
from contextlib import asynccontextmanager

from astrbot.api import logger

from .....config.plugin import get_plugin_config
from .breaker import MediaDownloadFlowBreakerMixin
from .config import MediaDownloadFlowConfigMixin
from .rate import MediaDownloadFlowRateMixin
from .state import MediaDownloadFlowStateMixin


class MediaDownloadFlowControlMixin(
    MediaDownloadFlowConfigMixin,
    MediaDownloadFlowStateMixin,
    MediaDownloadFlowBreakerMixin,
    MediaDownloadFlowRateMixin,
):
    """Shared flow-control primitives for media download operations."""

    pass


# Preserve direct class attributes and method descriptors exposed by the former mixin.
MediaDownloadFlowControlMixin._MEDIA_DOWNLOAD_CONCURRENCY_DEFAULT = (
    MediaDownloadFlowConfigMixin.__dict__["_MEDIA_DOWNLOAD_CONCURRENCY_DEFAULT"]
)
MediaDownloadFlowControlMixin._MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES_DEFAULT = (
    MediaDownloadFlowConfigMixin.__dict__["_MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES_DEFAULT"]
)
MediaDownloadFlowControlMixin._ensure_media_download_flow_control = (
    MediaDownloadFlowStateMixin.__dict__["_ensure_media_download_flow_control"]
)
MediaDownloadFlowControlMixin._normalize_media_source_key = (
    MediaDownloadFlowConfigMixin.__dict__["_normalize_media_source_key"]
)
MediaDownloadFlowControlMixin._get_media_download_concurrency_limit = (
    MediaDownloadFlowConfigMixin.__dict__["_get_media_download_concurrency_limit"]
)
MediaDownloadFlowControlMixin._get_media_download_max_in_memory_bytes = (
    MediaDownloadFlowConfigMixin.__dict__["_get_media_download_max_in_memory_bytes"]
)
MediaDownloadFlowControlMixin._get_media_download_min_interval_seconds = (
    MediaDownloadFlowConfigMixin.__dict__["_get_media_download_min_interval_seconds"]
)
MediaDownloadFlowControlMixin._get_media_download_breaker_fail_threshold = (
    MediaDownloadFlowConfigMixin.__dict__["_get_media_download_breaker_fail_threshold"]
)
MediaDownloadFlowControlMixin._get_media_download_breaker_base_cooldown_seconds = (
    MediaDownloadFlowConfigMixin.__dict__[
        "_get_media_download_breaker_base_cooldown_seconds"
    ]
)
MediaDownloadFlowControlMixin._get_media_download_breaker_max_cooldown_seconds = (
    MediaDownloadFlowConfigMixin.__dict__[
        "_get_media_download_breaker_max_cooldown_seconds"
    ]
)
MediaDownloadFlowControlMixin._is_media_download_breaker_enabled = (
    MediaDownloadFlowConfigMixin.__dict__["_is_media_download_breaker_enabled"]
)
MediaDownloadFlowControlMixin._is_media_download_breaker_failure_status = (
    MediaDownloadFlowBreakerMixin.__dict__["_is_media_download_breaker_failure_status"]
)
MediaDownloadFlowControlMixin._wait_media_download_breaker = (
    MediaDownloadFlowBreakerMixin.__dict__["_wait_media_download_breaker"]
)
MediaDownloadFlowControlMixin._record_media_download_success = (
    MediaDownloadFlowBreakerMixin.__dict__["_record_media_download_success"]
)
MediaDownloadFlowControlMixin._record_media_download_failure = (
    MediaDownloadFlowBreakerMixin.__dict__["_record_media_download_failure"]
)
MediaDownloadFlowControlMixin._get_media_download_semaphore = (
    MediaDownloadFlowRateMixin.__dict__["_get_media_download_semaphore"]
)
MediaDownloadFlowControlMixin._apply_media_download_rate_limit = (
    MediaDownloadFlowRateMixin.__dict__["_apply_media_download_rate_limit"]
)
MediaDownloadFlowControlMixin._media_download_slot = (
    MediaDownloadFlowRateMixin.__dict__["_media_download_slot"]
)


__all__ = [
    "MediaDownloadFlowControlMixin",
    "asynccontextmanager",
    "asyncio",
    "get_plugin_config",
    "logger",
    "time",
]
