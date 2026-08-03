from __future__ import annotations

import copy
from typing import Any


class MatrixOutboundRecordsMixin:
    """Persist outbound attempt records and summaries."""

    def record_attempt(
        self,
        *,
        txn_id: str,
        action: str,
        room_id: str,
        event_type: str,
        content: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        existing = self.store.get(txn_id) or {}
        attempts = int(existing.get("attempts") or 0) + 1
        created_at = int(existing.get("created_at") or self._now_ms())
        record = {
            "txn_id": txn_id,
            "action": action,
            "room_id": room_id,
            "event_type": event_type,
            "content": copy.deepcopy(content) if isinstance(content, dict) else {},
            "state": "pending",
            "attempts": attempts,
            "created_at": created_at,
            "updated_at": self._now_ms(),
            "last_error": None,
            "event_id": existing.get("event_id"),
            "metadata": metadata or existing.get("metadata") or {},
        }
        self.store.upsert(txn_id, record)
        self._remember_key(txn_id)

    def mark_success(self, txn_id: str, response: dict[str, Any] | None) -> None:
        record = self.store.get(txn_id) or {"txn_id": txn_id}
        record["state"] = "sent"
        record["updated_at"] = self._now_ms()
        record["last_error"] = None
        if isinstance(response, dict):
            record["event_id"] = response.get("event_id") or record.get("event_id")
        self.store.upsert(txn_id, record)
        self._remember_key(txn_id)

    def mark_failure(self, txn_id: str, error: Exception | str) -> None:
        record = self.store.get(txn_id) or {"txn_id": txn_id}
        record["state"] = "failed"
        record["updated_at"] = self._now_ms()
        record["last_error"] = str(error)
        self.store.upsert(txn_id, record)
        self._remember_key(txn_id)

    def list_records(
        self, *, states: set[str] | None = None, limit: int = 20
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for key in reversed(self._load_keys()):
            record = self.store.get(key)
            if not isinstance(record, dict):
                continue
            if states and record.get("state") not in states:
                continue
            results.append(record)
            if len(results) >= limit:
                break
        return results

    def summary(self) -> dict[str, Any]:
        counts = {"pending": 0, "failed": 0, "sent": 0}
        for key in self._load_keys():
            record = self.store.get(key)
            if not isinstance(record, dict):
                continue
            state = str(record.get("state") or "")
            if state in counts:
                counts[state] += 1
        return counts
