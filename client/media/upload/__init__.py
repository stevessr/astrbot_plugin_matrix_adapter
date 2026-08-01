"""Composable Matrix media upload mixins."""

from .bytes import MediaUploadBytesMixin
from .cache import MediaUploadCacheMixin
from .common import MediaUploadConfigMixin
from .endpoint import MediaUploadEndpointMixin
from .file import MediaUploadFileMixin
from .retry import MediaUploadRetryMixin


class MediaUploadMixin(
    MediaUploadBytesMixin,
    MediaUploadFileMixin,
    MediaUploadEndpointMixin,
    MediaUploadRetryMixin,
    MediaUploadCacheMixin,
    MediaUploadConfigMixin,
):
    """Combined upload implementation consumed by the media client."""

    pass


__all__ = ["MediaUploadMixin"]
