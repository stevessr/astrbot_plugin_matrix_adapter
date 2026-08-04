"""Media-cache directory, key, lookup, and cleanup operations.

Public symbols re-exported for backward compatibility.
"""

from .build import MatrixReceiverMediaCacheBuildMixin
from .dirs import MatrixReceiverMediaCacheDirsMixin
from .gc import MatrixReceiverMediaCacheGcMixin
from .keys import MatrixReceiverMediaCacheKeysMixin


class MatrixReceiverMediaCachePathsMixin(
    MatrixReceiverMediaCacheDirsMixin,
    MatrixReceiverMediaCacheKeysMixin,
    MatrixReceiverMediaCacheBuildMixin,
    MatrixReceiverMediaCacheGcMixin,
):
    """Resolve media-cache paths and garbage-collect stale files."""


__all__ = [
    "MatrixReceiverMediaCacheBuildMixin",
    "MatrixReceiverMediaCacheDirsMixin",
    "MatrixReceiverMediaCacheGcMixin",
    "MatrixReceiverMediaCacheKeysMixin",
    "MatrixReceiverMediaCachePathsMixin",
]
