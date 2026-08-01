"""Shared configuration for Matrix media uploads."""


class MediaUploadConfigMixin:
    """Constants shared by upload cache, retry, and transport mixins."""

    _MEDIA_UPLOAD_CACHE_TTL_SECONDS = 15 * 60

    _MEDIA_UPLOAD_CACHE_MAX_ENTRIES = 256

    _MEDIA_HTTP_MAX_RETRIES = 3

    _MEDIA_RETRY_BASE_DELAY_SECONDS = 0.75

    _MEDIA_RETRY_MAX_DELAY_SECONDS = 10.0

    _MEDIA_UPLOAD_SNIFF_BYTES = 4096

    _MEDIA_UPLOAD_POLL_TIMEOUT_SECONDS = 120.0

    _MEDIA_UPLOAD_POLL_INTERVAL_SECONDS = 0.5
