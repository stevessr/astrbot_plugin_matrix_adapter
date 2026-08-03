"""Composable full-path Matrix media upload operations."""

import asyncio  # noqa: F401
from pathlib import Path  # noqa: F401
from typing import Any  # noqa: F401

import aiohttp  # noqa: F401

from astrbot.api import logger  # noqa: F401

from .....constants import HTTP_ERROR_STATUS_400  # noqa: F401
from .upload import MediaUploadFileOperationMixin


class MediaUploadFileMixin(MediaUploadFileOperationMixin):
    """Upload local files without buffering the complete file in memory."""

    pass


# Preserve direct method attributes exposed by the former mixin.
MediaUploadFileMixin.upload_file_path = MediaUploadFileOperationMixin.__dict__[
    "upload_file_path"
]


__all__ = [
    "Any",
    "HTTP_ERROR_STATUS_400",
    "MediaUploadFileMixin",
    "Path",
    "aiohttp",
    "asyncio",
    "logger",
]
