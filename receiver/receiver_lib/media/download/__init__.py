"""Media download, decryption, and background-task primitives.

Public symbol re-exported for backward compatibility.
"""

from .cache import MatrixReceiverMediaCacheMixin
from .encrypted import MatrixReceiverMediaEncryptedDownloadMixin
from .plain import MatrixReceiverMediaPlainDownloadMixin
from .tasks import MatrixReceiverMediaTasksMixin


class MatrixReceiverMediaDownloadMixin(
    MatrixReceiverMediaTasksMixin,
    MatrixReceiverMediaCacheMixin,
    MatrixReceiverMediaPlainDownloadMixin,
    MatrixReceiverMediaEncryptedDownloadMixin,
):
    """Download plain or encrypted media into the receiver cache."""


__all__ = [
    "MatrixReceiverMediaCacheMixin",
    "MatrixReceiverMediaDownloadMixin",
    "MatrixReceiverMediaEncryptedDownloadMixin",
    "MatrixReceiverMediaPlainDownloadMixin",
    "MatrixReceiverMediaTasksMixin",
]
