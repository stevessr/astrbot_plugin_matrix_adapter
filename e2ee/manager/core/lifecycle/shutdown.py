import asyncio

from astrbot.api import logger


class E2EEManagerCoreLifecycleShutdownMixin:
    async def close(self) -> None:
        """Release runtime resources and flush pending persistence jobs."""
        self._closing = True
        self._initialized = False
        key_share_task = self.stop_key_share_check_task()
        if key_share_task and not key_share_task.done():
            try:
                await key_share_task
            except asyncio.CancelledError:
                pass
        store = self._store
        self._store = None
        self._olm = None
        self._verification = None
        self._key_backup = None
        self._cross_signing = None
        self._pending_room_key_requests.clear()
        self._room_key_share_locks.clear()
        self._room_encryption_config.clear()
        self._no_olm_withheld_sent.clear()
        self._olm_recovery_attempts.clear()
        self._room_key_withheld.clear()
        if store is not None and hasattr(store, "close"):
            try:
                await asyncio.to_thread(store.close)
            except Exception as e:
                logger.warning(f"E2EE store close failed: {e}")
