from .convert import MatrixReceiverConvertMixin
from .media import MatrixReceiverMediaMixin
from .media_cache import MatrixReceiverMediaCacheMixin


class MatrixReceiverMixin(
    MatrixReceiverMediaMixin,
    MatrixReceiverMediaCacheMixin,
    MatrixReceiverConvertMixin,
):
    """Combined receiver mixin."""

    pass


__all__ = [
    "MatrixReceiverMediaMixin",
    "MatrixReceiverMediaCacheMixin",
    "MatrixReceiverConvertMixin",
    "MatrixReceiverMixin",
]
