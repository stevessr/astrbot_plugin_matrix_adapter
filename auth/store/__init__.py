"""Layered authentication token storage helpers."""

from .backend import MatrixAuthStoreBackendMixin
from .file import MatrixAuthStoreFileMixin
from .paths import MatrixAuthStorePathsMixin
from .token import MatrixAuthStoreTokenMixin


class MatrixAuthStore(
    MatrixAuthStorePathsMixin,
    MatrixAuthStoreBackendMixin,
    MatrixAuthStoreFileMixin,
    MatrixAuthStoreTokenMixin,
):
    """Compose authentication token storage operations."""

    pass


__all__ = [
    "MatrixAuthStore",
    "MatrixAuthStoreBackendMixin",
    "MatrixAuthStoreFileMixin",
    "MatrixAuthStorePathsMixin",
    "MatrixAuthStoreTokenMixin",
]
