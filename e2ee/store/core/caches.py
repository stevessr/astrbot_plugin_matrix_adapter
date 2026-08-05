"""In-memory cache containers for the crypto store."""

import threading
from typing import Any


class CryptoStoreCoreCachesMixin:
    """Initialize the in-memory record caches."""

    def _init_memory_caches(self) -> None:
        # 内存缓存
        self._account_pickle: str | None = None
        self._olm_sessions: dict[str, list[str]] = {}  # sender_key -> [session_pickles]
        self._megolm_inbound: dict[str, str] = {}  # session_id -> pickle
        self._megolm_inbound_meta: dict[str, dict[str, Any]] = {}
        self._megolm_replay: dict[str, dict[str, str]] = {}
        self._megolm_replay_lock = threading.Lock()
        self._megolm_outbound: dict[str, str] = {}  # room_id -> pickle
        self._megolm_outbound_meta: dict[str, dict[str, Any]] = {}
        self._device_keys: dict[str, dict] = {}  # user_id -> {device_id: keys}


__all__ = ["CryptoStoreCoreCachesMixin"]
