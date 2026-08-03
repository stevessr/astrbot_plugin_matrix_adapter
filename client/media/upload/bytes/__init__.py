"""Composable in-memory Matrix media upload operations."""

import asyncio  # noqa: F401
from typing import Any  # noqa: F401

import aiohttp  # noqa: F401

from astrbot.api import logger  # noqa: F401

from .....constants import HTTP_ERROR_STATUS_400  # noqa: F401
from .upload import MediaUploadBytesOperationMixin


class MediaUploadBytesMixin(MediaUploadBytesOperationMixin):
    """Upload in-memory media with retry and async-upload support."""

    pass


# Preserve direct method attributes exposed by the former mixin.
MediaUploadBytesMixin.upload_file = MediaUploadBytesOperationMixin.__dict__[
    "upload_file"
]


__all__ = [
    "Any",
    "HTTP_ERROR_STATUS_400",
    "MediaUploadBytesMixin",
    "aiohttp",
    "asyncio",
    "logger",
]
