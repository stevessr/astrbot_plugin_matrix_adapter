"""Layered Matrix storage path utilities."""

from .layout import StoragePathLayoutMixin
from .migration import StoragePathMigrationMixin
from .naming import StoragePathNamingMixin


class MatrixStoragePaths(
    StoragePathNamingMixin,
    StoragePathLayoutMixin,
    StoragePathMigrationMixin,
):
    """无状态的 Matrix 存储路径转换工具。"""

    def __init__(self):
        raise TypeError(
            "MatrixStoragePaths is a static utility class and should not be instantiated"
        )


__all__ = [
    "MatrixStoragePaths",
    "StoragePathNamingMixin",
    "StoragePathLayoutMixin",
    "StoragePathMigrationMixin",
]
