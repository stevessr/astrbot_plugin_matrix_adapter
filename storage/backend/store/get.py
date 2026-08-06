"""Folder-scoped data store read operations."""

from typing import Any

from astrbot.api import logger


class MatrixFolderDataStoreGetMixin:
    """Read records with legacy-json fallback and migration."""

    def get(self, record_key: str) -> Any | None:
        """Read one record from selected backend."""
        if not record_key:
            return None

        data = self._backend_impl.get(record_key)
        if data is not None:
            return data

        # Non-json backend: fallback to legacy json files and auto-migrate.
        if self.backend != "json":
            legacy = self._json_backend.get(record_key)
            if legacy is not None:
                try:
                    self._backend_impl.upsert(record_key, legacy)
                except Exception as e:
                    logger.debug(
                        f"Failed to migrate legacy json for {self.namespace_key}:{record_key}: {e}"
                    )
            return legacy

        return None


__all__ = ["MatrixFolderDataStoreGetMixin"]
