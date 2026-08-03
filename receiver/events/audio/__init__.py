"""Inbound Matrix audio event helpers."""

from astrbot.api import logger
from astrbot.api.message_components import Plain, Record

from ....constants import M_MEDIA_KEY, MSC1767_AUDIO_KEY, MSC1767_FILE_KEY
from ..text import append_formatted_text, should_append_caption
from .extraction import (
    _MEDIA,
    _extract_audio_file_info,
    _extract_audio_filename,
    _extract_audio_info,
    _extract_audio_size,
    _extract_audio_url,
    _extract_media_block,
    _extract_unstable_file,
)
from .handler import handle_audio

__all__ = [
    "M_MEDIA_KEY",
    "MSC1767_AUDIO_KEY",
    "MSC1767_FILE_KEY",
    "Plain",
    "Record",
    "_MEDIA",
    "_extract_audio_file_info",
    "_extract_audio_filename",
    "_extract_audio_info",
    "_extract_audio_size",
    "_extract_audio_url",
    "_extract_media_block",
    "_extract_unstable_file",
    "append_formatted_text",
    "handle_audio",
    "logger",
    "should_append_caption",
]
