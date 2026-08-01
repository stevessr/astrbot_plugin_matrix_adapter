"""
Matrix 消息接收组件
"""

import asyncio
from pathlib import Path

from ..constants import (
    MSGTYPE_AUDIO,
    MSGTYPE_EMOTE,
    MSGTYPE_FILE,
    MSGTYPE_IMAGE,
    MSGTYPE_LOCATION,
    MSGTYPE_NOTICE,
    MSGTYPE_REDACTION,
    MSGTYPE_STICKER,
    MSGTYPE_TEXT,
    MSGTYPE_VIDEO,
)

# Kept importable: tests patch receiver.core.get_plugin_config to stub
# plugin config. The mixin modules import it directly from ..plugin_config.
from ..plugin_config import get_plugin_config  # noqa: F401
from ..utils.media_cache_index import MediaCacheIndexStore
from .handlers import (
    handle_audio,
    handle_file,
    handle_image,
    handle_location,
    handle_reaction,
    handle_redaction,
    handle_sticker,
    handle_text,
    handle_video,
)
from .receiver_lib import (
    MatrixReceiverConvertMixin,
    MatrixReceiverMediaCacheMixin,
    MatrixReceiverMediaMixin,
)


class MatrixReceiver(
    MatrixReceiverMediaMixin,
    MatrixReceiverMediaCacheMixin,
    MatrixReceiverConvertMixin,
):
    """Combined MatrixReceiver: media download, media cache, event conversion."""

    _REPLY_EVENT_FETCH_TIMEOUT_SECONDS = 2.0
    _QUOTED_MEDIA_DOWNLOAD_TIMEOUT_SECONDS = 2.5
    _QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY_DEFAULT = 2
    _IMAGE_EXTENSIONS = {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".bmp",
        ".svg",
        ".avif",
        ".heic",
        ".heif",
    }

    # 消息类型 -> handler 映射（类常量，避免每次 convert_message 时重建）
    _MSGTYPE_HANDLERS = {
        MSGTYPE_TEXT: handle_text,
        MSGTYPE_NOTICE: handle_text,
        MSGTYPE_EMOTE: handle_text,
        MSGTYPE_IMAGE: handle_image,
        MSGTYPE_REDACTION: handle_redaction,
        MSGTYPE_STICKER: handle_sticker,
        MSGTYPE_VIDEO: handle_video,
        MSGTYPE_AUDIO: handle_audio,
        MSGTYPE_FILE: handle_file,
        "m.reaction": handle_reaction,
        MSGTYPE_LOCATION: handle_location,
    }

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
