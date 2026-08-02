"""Sync token access and persistence operations."""


class MatrixSyncManagerTokenMixin:
    """Manage sync tokens in storage and legacy attributes."""

    def _get_next_batch(self) -> str | None:
        """Get the current sync token from the token store (or legacy attr)."""
        if hasattr(self, "_next_batch") and self._next_batch is not None:
            return self._next_batch
        if hasattr(self, "_token_store") and self._token_store is not None:
            return self._token_store.next_batch
        return None

    def _set_next_batch(self, batch: str) -> None:
        """Set the sync token on both the store and the legacy attr."""
        self._next_batch = batch
        if hasattr(self, "_token_store") and self._token_store is not None:
            self._token_store.next_batch = batch

    async def _save_sync_token(self, *, force: bool = False) -> None:
        """Persist current sync token to storage."""
        if hasattr(self, "_token_store") and self._token_store is not None:
            await self._token_store.save(force=force)

    def get_next_batch(self) -> str | None:
        """Get the current sync token."""
        return self._get_next_batch()

    def set_next_batch(self, batch: str):
        """Override the sync token (for resumption)."""
        self._set_next_batch(batch)
        self._first_sync = False
