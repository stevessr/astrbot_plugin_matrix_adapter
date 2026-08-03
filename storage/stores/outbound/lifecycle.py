"""Outbound tracker key lifecycle operations."""

import time


class MatrixOutboundLifecycleMixin:
    """Track timestamps and the bounded recent transaction key list."""

    def _now_ms(self) -> int:
        return int(time.time() * 1000)

    def _remember_key(self, txn_id: str) -> None:
        keys = self.store.get(self._recent_keys_key) or []
        if txn_id in keys:
            keys = [k for k in keys if k != txn_id]
        keys.append(txn_id)
        if len(keys) > self._record_limit:
            keys = keys[-self._record_limit :]
        self.store.upsert(self._recent_keys_key, keys)

    def _load_keys(self) -> list[str]:
        keys = self.store.get(self._recent_keys_key) or []
        if not isinstance(keys, list):
            return []
        return [str(key) for key in keys if str(key or "").strip()]
