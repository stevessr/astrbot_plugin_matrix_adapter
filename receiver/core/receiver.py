"""Composed Matrix receiver implementation."""

import asyncio
from pathlib import Path

from ...utils.media_cache_index import MediaCacheIndexStore
from ..receiver_lib import (
    MatrixReceiverConvertMixin,
    MatrixReceiverMediaCacheMixin,
    MatrixReceiverMediaMixin,
)
from .handlers import MESSAGE_TYPE_HANDLERS
from .settings import (
    IMAGE_EXTENSIONS,
    QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY_DEFAULT,
    QUOTED_MEDIA_DOWNLOAD_TIMEOUT_SECONDS,
    REPLY_EVENT_FETCH_TIMEOUT_SECONDS,
)


class MatrixReceiver(
    MatrixReceiverMediaMixin,
    MatrixReceiverMediaCacheMixin,
    MatrixReceiverConvertMixin,
):
    """Combined MatrixReceiver: media download, media cache, event conversion."""

    _REPLY_EVENT_FETCH_TIMEOUT_SECONDS = REPLY_EVENT_FETCH_TIMEOUT_SECONDS
    _QUOTED_MEDIA_DOWNLOAD_TIMEOUT_SECONDS = QUOTED_MEDIA_DOWNLOAD_TIMEOUT_SECONDS
    _QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY_DEFAULT = (
        QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY_DEFAULT
    )
    _IMAGE_EXTENSIONS = IMAGE_EXTENSIONS
    _MSGTYPE_HANDLERS = MESSAGE_TYPE_HANDLERS

    def __init__(
        self,
        user_id: str,
        mxc_converter: callable = None,
        bot_name: str = "MatrixBot",
        client=None,
    ):
        self.user_id = user_id
        self.mxc_converter = mxc_converter
        self.bot_name = bot_name
        self.client = client  # MatrixHTTPClient instance needed for downloading files
        self._media_download_tasks: dict[str, asyncio.Task[Path]] = {}
        self._background_tasks: set[asyncio.Task] = set()
        self._quoted_media_background_download_concurrency = (
            self._get_quoted_media_background_download_concurrency()
        )
        self._quoted_media_background_download_semaphore = asyncio.Semaphore(
            self._quoted_media_background_download_concurrency
        )
        self._media_cache_index: dict[str, Path] = {}
        self._media_cache_index_store: MediaCacheIndexStore | None = None
        self._initialize_media_cache_index_store()
