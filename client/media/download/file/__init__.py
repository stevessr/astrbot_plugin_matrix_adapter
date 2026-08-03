"""Composable full-size Matrix media download operations."""

import asyncio  # noqa: F401
from pathlib import Path  # noqa: F401
from typing import Any  # noqa: F401
from urllib.parse import urlencode  # noqa: F401

import aiohttp  # noqa: F401

from astrbot.api import logger  # noqa: F401

from ....path_utils import quote_path_segment  # noqa: F401
from .download import MediaDownloadFileOperationMixin


class MediaDownloadFileMixin(MediaDownloadFileOperationMixin):
    """Download full-size media with retry and thumbnail fallback support."""

    pass


# Preserve direct method attributes exposed by the former mixin.
MediaDownloadFileMixin.download_file = MediaDownloadFileOperationMixin.__dict__[
    "download_file"
]


__all__ = [
    "Any",
    "MediaDownloadFileMixin",
    "Path",
    "aiohttp",
    "asyncio",
    "logger",
    "quote_path_segment",
    "urlencode",
]
