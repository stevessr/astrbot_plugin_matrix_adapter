"""Composable Matrix receiver media-cache index operations."""

import mimetypes
import time
from pathlib import Path

from astrbot.api import logger
from astrbot.core.utils import astrbot_path

from .....config.plugin import get_plugin_config
from .....utils.media_cache_index import MediaCacheIndexStore
from .paths import MatrixReceiverMediaCachePathsMixin
from .persistence import MatrixReceiverMediaCachePersistenceMixin


class MatrixReceiverMediaCacheOperationsMixin(
    MatrixReceiverMediaCachePersistenceMixin,
    MatrixReceiverMediaCachePathsMixin,
):
    """Aggregate persistent index and cache path operations."""

    pass


# Preserve direct methods exposed by the former index mixin.
for _mixin in (
    MatrixReceiverMediaCachePersistenceMixin,
    MatrixReceiverMediaCachePathsMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixReceiverMediaCacheOperationsMixin, _method_name, _method)


__all__ = [
    "MatrixReceiverMediaCacheOperationsMixin",
    "MatrixReceiverMediaCachePathsMixin",
    "MatrixReceiverMediaCachePersistenceMixin",
    "MediaCacheIndexStore",
    "Path",
    "astrbot_path",
    "get_plugin_config",
    "logger",
    "mimetypes",
    "time",
]
