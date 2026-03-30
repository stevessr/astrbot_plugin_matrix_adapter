from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class MatrixRuntimeErrorEntry:
    category: str
    message: str
    ts: str = field(default_factory=_utc_now_iso)


class MatrixRuntimeState:
    """Tracks runtime health for one Matrix adapter instance."""

    def __init__(self, max_recent_errors: int = 20):
        self.started_at = _utc_now_iso()
        self.lifecycle_state = "initialized"
        self.auth_state = "idle"
        self.sync_state = "idle"
        self.last_auth_success_at: str | None = None
        self.last_sync_success_at: str | None = None
        self.last_send_success_at: str | None = None
        self.last_presence_update_at: str | None = None
        self.last_reconnect_request_at: str | None = None
        self.last_error_at: str | None = None
        self.last_error_category: str | None = None
        self.last_error_message: str | None = None
        self.send_success_count = 0
        self.send_failure_count = 0
        self.reconnect_requests = 0
        self._recent_errors: deque[MatrixRuntimeErrorEntry] = deque(
            maxlen=max_recent_errors
        )

    def record_error(self, category: str, message: str) -> None:
        entry = MatrixRuntimeErrorEntry(category=category, message=str(message))
        self._recent_errors.appendleft(entry)
        self.last_error_at = entry.ts
        self.last_error_category = category
        self.last_error_message = str(message)
        if category == "auth":
            self.auth_state = "error"
        elif category == "sync":
            self.sync_state = "error"

    def mark_lifecycle(self, state: str) -> None:
        self.lifecycle_state = state

    def mark_auth_started(self) -> None:
        self.auth_state = "running"

    def mark_auth_ok(self) -> None:
        self.auth_state = "ready"
        self.last_auth_success_at = _utc_now_iso()

    def mark_sync_started(self) -> None:
        self.sync_state = "running"

    def mark_sync_ok(self) -> None:
        self.sync_state = "running"
        self.last_sync_success_at = _utc_now_iso()

    def mark_sync_stopped(self) -> None:
        self.sync_state = "stopped"

    def mark_send_ok(self) -> None:
        self.send_success_count += 1
        self.last_send_success_at = _utc_now_iso()

    def mark_send_failed(self, message: str) -> None:
        self.send_failure_count += 1
        self.record_error("send", message)

    def mark_presence_updated(self) -> None:
        self.last_presence_update_at = _utc_now_iso()

    def mark_reconnect_requested(self) -> None:
        self.reconnect_requests += 1
        self.last_reconnect_request_at = _utc_now_iso()

    def recent_errors(self) -> list[dict[str, str]]:
        return [
            {"ts": item.ts, "category": item.category, "message": item.message}
            for item in self._recent_errors
        ]

    def snapshot(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "lifecycle_state": self.lifecycle_state,
            "auth_state": self.auth_state,
            "sync_state": self.sync_state,
            "last_auth_success_at": self.last_auth_success_at,
            "last_sync_success_at": self.last_sync_success_at,
            "last_send_success_at": self.last_send_success_at,
            "last_presence_update_at": self.last_presence_update_at,
            "last_reconnect_request_at": self.last_reconnect_request_at,
            "last_error_at": self.last_error_at,
            "last_error_category": self.last_error_category,
            "last_error_message": self.last_error_message,
            "send_success_count": self.send_success_count,
            "send_failure_count": self.send_failure_count,
            "reconnect_requests": self.reconnect_requests,
            "recent_errors": self.recent_errors(),
        }
