"""Outbound Matrix music event helpers."""

import mimetypes
import uuid
from pathlib import Path

import aiohttp

from astrbot.api import logger
from astrbot.api.message_components import Music
from astrbot.core.utils.astrbot_path import get_astrbot_data_path

from ....config.plugin import get_plugin_config
from ....constants import DEFAULT_MAX_UPLOAD_SIZE_BYTES
from ..common import resolve_text_msgtype, send_content
from .download import (
    _MUSIC_DOWNLOAD_CHUNK_SIZE,
    _MUSIC_DOWNLOAD_CONNECT_TIMEOUT_SECONDS,
    _download_music_with_limit,
    _resolve_music_download_total_timeout_seconds,
)
from .handler import _send_music


async def send_music(
    client,
    segment: Music,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
    upload_size_limit: int | None = None,
    thread_is_falling_back: bool | None = None,
    use_notice: bool = False,
) -> None:
    """Send a Matrix music event."""
    return await _send_music(
        client,
        segment,
        room_id,
        reply_to,
        thread_root,
        use_thread,
        is_encrypted_room,
        e2ee_manager,
        upload_size_limit=upload_size_limit,
        thread_is_falling_back=thread_is_falling_back,
        use_notice=use_notice,
        send_content_fn=send_content,
        download_music_fn=_download_music_with_limit,
        resolve_text_msgtype_fn=resolve_text_msgtype,
        get_data_path_fn=get_astrbot_data_path,
        logger_obj=logger,
        max_upload_size_bytes=DEFAULT_MAX_UPLOAD_SIZE_BYTES,
    )


__all__ = [
    "DEFAULT_MAX_UPLOAD_SIZE_BYTES",
    "Music",
    "Path",
    "_MUSIC_DOWNLOAD_CHUNK_SIZE",
    "_MUSIC_DOWNLOAD_CONNECT_TIMEOUT_SECONDS",
    "_download_music_with_limit",
    "_resolve_music_download_total_timeout_seconds",
    "aiohttp",
    "get_astrbot_data_path",
    "get_plugin_config",
    "logger",
    "mimetypes",
    "resolve_text_msgtype",
    "send_content",
    "send_music",
    "uuid",
]
