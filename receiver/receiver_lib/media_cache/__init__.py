"""Composable Matrix receiver media cache operations."""

import mimetypes  # noqa: F401
import time  # noqa: F401
from pathlib import Path  # noqa: F401

from astrbot.api import logger  # noqa: F401
from astrbot.core.utils import astrbot_path  # noqa: F401

from ....config.plugin import get_plugin_config  # noqa: F401
from ....utils.media_cache_index import MediaCacheIndexStore  # noqa: F401
from .index import MatrixReceiverMediaCacheOperationsMixin


class MatrixReceiverMediaCacheMixin(MatrixReceiverMediaCacheOperationsMixin):
    """MatrixReceiver 媒体缓存索引与路径 mixin"""

    pass


# Preserve direct method attributes exposed by the former mixin.
for _method_name, _method in MatrixReceiverMediaCacheOperationsMixin.__dict__.items():
    if callable(_method) and not _method_name.startswith("__"):
        setattr(MatrixReceiverMediaCacheMixin, _method_name, _method)


__all__ = [
    "MatrixReceiverMediaCacheMixin",
    "MediaCacheIndexStore",
    "Path",
    "astrbot_path",
    "get_plugin_config",
    "logger",
    "mimetypes",
    "time",
]
