"""Folder-scoped multi-backend data store."""

from __future__ import annotations

from .get import MatrixFolderDataStoreGetMixin
from .init import MatrixFolderDataStoreInitMixin
from .write import MatrixFolderDataStoreWriteMixin


class MatrixFolderDataStore(
    MatrixFolderDataStoreInitMixin,
    MatrixFolderDataStoreGetMixin,
    MatrixFolderDataStoreWriteMixin,
):
    """
    Multi-backend key-value store scoped to one folder namespace.

    For json backend: key -> `<sanitized_key>.json` (or custom filename resolver)
    For sqlite backend: key -> row in `<folder>/<folder_name>.db`
    For pgsql backend: key -> row in one table mapped from folder namespace
    """


__all__ = ["MatrixFolderDataStore"]
