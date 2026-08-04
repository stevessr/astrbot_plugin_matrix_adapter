"""Sync response event routing for the Matrix sync manager."""

import asyncio


class MatrixSyncManagerEventRoutingCoreMixin:
    """Dispatch sync response fields to registered callbacks."""

    async def _dispatch_events(self, sync_response: dict) -> None:
        """Dispatch sync response fields to registered callbacks."""
        tasks: list[asyncio.Task] = []

        self._dispatch_global_fields(sync_response, tasks)

        # 6. Room events — process in parallel
        self._dispatch_room_fields(sync_response, tasks)

        # Track and await all callbacks
        self._active_callback_tasks.update(tasks)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._active_callback_tasks.difference_update(tasks)
