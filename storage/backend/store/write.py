"""Folder-scoped data store write operations."""

from typing import Any


class MatrixFolderDataStoreWriteMixin:
    """Create, update, and delete records."""

    def upsert(self, record_key: str, data: Any) -> None:
        """Create or update one record."""
        if not record_key:
            return
        self._backend_impl.upsert(record_key, data)

    def delete(self, record_key: str) -> None:
        """Delete one record."""
        if not record_key:
            return
        self._backend_impl.delete(record_key)


__all__ = ["MatrixFolderDataStoreWriteMixin"]
