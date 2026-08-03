"""Composable full-path Matrix media upload operation."""

import asyncio
from pathlib import Path
from typing import Any

import aiohttp

from astrbot.api import logger

from ......constants import HTTP_ERROR_STATUS_400
from .primary import MediaUploadPrimaryMixin
from .transfer import MediaUploadTransferMixin


class MediaUploadFileOperationMixin(MediaUploadPrimaryMixin, MediaUploadTransferMixin):
    """Upload local files without buffering the complete file in memory."""

    pass


for _mixin in (MediaUploadPrimaryMixin, MediaUploadTransferMixin):
    for _method_name, _method in _mixin.__dict__.items():
        if callable(_method) and not _method_name.startswith("__"):
            setattr(MediaUploadFileOperationMixin, _method_name, _method)


__all__ = [
    "Any",
    "HTTP_ERROR_STATUS_400",
    "MediaUploadFileOperationMixin",
    "Path",
    "aiohttp",
    "asyncio",
    "logger",
]
