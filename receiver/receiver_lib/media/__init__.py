"""Composable receiver media handling mixins."""

from .download import MatrixReceiverMediaDownloadMixin
from .lifecycle import MatrixReceiverMediaLifecycleMixin
from .policy import MatrixReceiverMediaPolicyMixin
from .quoted import MatrixReceiverQuotedMediaMixin


class MatrixReceiverMediaMixin(
    MatrixReceiverMediaPolicyMixin,
    MatrixReceiverMediaDownloadMixin,
    MatrixReceiverQuotedMediaMixin,
    MatrixReceiverMediaLifecycleMixin,
):
    """Combined media policy, download, quoted-media, and lifecycle behavior."""

    pass


__all__ = [
    "MatrixReceiverMediaDownloadMixin",
    "MatrixReceiverMediaLifecycleMixin",
    "MatrixReceiverMediaMixin",
    "MatrixReceiverMediaPolicyMixin",
    "MatrixReceiverQuotedMediaMixin",
]
