"""Composable media MIME normalization and upload security helpers."""

import mimetypes
from pathlib import Path

from .....config.plugin import get_plugin_config
from .normalization import MediaMimeNormalizationMixin
from .policy import MediaMimePolicyMixin
from .sniffing import MediaMimeSniffingMixin
from .validation import MediaMimeValidationMixin


class MediaMimeMixin(
    MediaMimePolicyMixin,
    MediaMimeNormalizationMixin,
    MediaMimeSniffingMixin,
    MediaMimeValidationMixin,
):
    """Validate media uploads using extension, signature, and MIME policy."""

    pass


# Preserve direct class attributes and method descriptors exposed by the former mixin.
MediaMimeMixin._MEDIA_UPLOAD_DEFAULT_BLOCKED_EXTENSIONS = MediaMimePolicyMixin.__dict__[
    "_MEDIA_UPLOAD_DEFAULT_BLOCKED_EXTENSIONS"
]
MediaMimeMixin._MEDIA_UPLOAD_DEFAULT_ALLOWED_MIME_RULES = MediaMimePolicyMixin.__dict__[
    "_MEDIA_UPLOAD_DEFAULT_ALLOWED_MIME_RULES"
]
MediaMimeMixin._MEDIA_MIME_ALIASES = MediaMimeNormalizationMixin.__dict__[
    "_MEDIA_MIME_ALIASES"
]
MediaMimeMixin._normalize_mime_type = MediaMimeNormalizationMixin.__dict__[
    "_normalize_mime_type"
]
MediaMimeMixin._normalize_extension = MediaMimeNormalizationMixin.__dict__[
    "_normalize_extension"
]
MediaMimeMixin._is_media_upload_strict_mime_check_enabled = (
    MediaMimePolicyMixin.__dict__["_is_media_upload_strict_mime_check_enabled"]
)
MediaMimeMixin._get_media_upload_blocked_extensions = MediaMimePolicyMixin.__dict__[
    "_get_media_upload_blocked_extensions"
]
MediaMimeMixin._get_media_upload_allowed_mime_rules = MediaMimePolicyMixin.__dict__[
    "_get_media_upload_allowed_mime_rules"
]
MediaMimeMixin._mime_allowed_by_rules = MediaMimeNormalizationMixin.__dict__[
    "_mime_allowed_by_rules"
]
MediaMimeMixin._is_mime_compatible = MediaMimeNormalizationMixin.__dict__[
    "_is_mime_compatible"
]
MediaMimeMixin._sniff_mime_from_bytes = MediaMimeSniffingMixin.__dict__[
    "_sniff_mime_from_bytes"
]
MediaMimeMixin._read_file_head = MediaMimeSniffingMixin.__dict__["_read_file_head"]
MediaMimeMixin._validate_media_upload_security = MediaMimeValidationMixin.__dict__[
    "_validate_media_upload_security"
]


__all__ = ["MediaMimeMixin", "Path", "get_plugin_config", "mimetypes"]
