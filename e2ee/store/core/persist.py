"""Persistence infrastructure for the crypto store."""

import threading
from concurrent.futures import Future, ThreadPoolExecutor

from ....config.plugin import get_plugin_config


class CryptoStoreCorePersistMixin:
    """Build the single-worker persistence executor and write budget."""

    def _init_persist_infrastructure(self) -> None:
        self._persist_executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="matrix-e2ee-store",
        )
        try:
            configured_pending_writes = int(
                get_plugin_config().e2ee_store_max_pending_writes
            )
        except Exception:
            configured_pending_writes = 256
        self._max_pending_writes = max(1, min(configured_pending_writes, 8192))
        self._persist_slots = threading.BoundedSemaphore(self._max_pending_writes)
        self._persist_futures: set[Future] = set()
        self._persist_futures_lock = threading.Lock()
        self._closed = False


__all__ = ["CryptoStoreCorePersistMixin"]
