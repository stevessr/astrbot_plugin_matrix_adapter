"""Composable full-size Matrix media download operation."""

import asyncio
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import aiohttp

from astrbot.api import logger

from .....path_utils import quote_path_segment
from .fallback import MediaDownloadThumbnailFallbackMixin
from .primary import MediaDownloadPrimaryMixin


class MediaDownloadFileOperationMixin(
    MediaDownloadPrimaryMixin,
    MediaDownloadThumbnailFallbackMixin,
):
    """Download full-size media with retry and thumbnail fallback support."""

    pass


for _mixin in (MediaDownloadPrimaryMixin, MediaDownloadThumbnailFallbackMixin):
    for _method_name, _method in _mixin.__dict__.items():
        if callable(_method) and not _method_name.startswith("__"):
            setattr(MediaDownloadFileOperationMixin, _method_name, _method)


__all__ = [
    "Any",
    "MediaDownloadFileOperationMixin",
    "Path",
    "aiohttp",
    "asyncio",
    "logger",
    "quote_path_segment",
    "urlencode",
]
