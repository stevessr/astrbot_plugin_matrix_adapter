"""Extraction of matrix_media settings from the config dictionary."""

from .core import _extract_media_settings
from .nested import _extract_media_block

__all__ = [
    "_extract_media_block",
    "_extract_media_settings",
]
