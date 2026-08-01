from .media import MatrixReceiverMediaMixin
from .media_cache import MatrixReceiverMediaCacheMixin
from .convert import MatrixReceiverConvertMixin


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
