"""Sync request execution."""


class MatrixSyncManagerLoopRequestMixin:
    """Execute one /sync request with the current filter."""

    async def _execute_sync_request(self):
        sync_kwargs = {
            "timeout": self.sync_timeout,
            "since": self._get_next_batch(),
        }
        filter_id = getattr(self, "_filter_id", None)
        if filter_id is not None:
            sync_kwargs["filter_id"] = filter_id
        return await self.client.sync(**sync_kwargs)


__all__ = ["MatrixSyncManagerLoopRequestMixin"]
