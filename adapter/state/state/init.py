"""Construction and error bookkeeping for runtime state."""

from collections import deque

from ..errors import MatrixRuntimeErrorEntry
from ..time import _utc_now_iso


class MatrixRuntimeStateInitMixin:
    """Initialize state fields and record runtime errors."""

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
        self.live_message_inbound_count = 0
        self.live_message_inbound_edit_count = 0
        self.live_message_outbound_initial_count = 0
        self.live_message_outbound_edit_count = 0
        self.last_live_message_at: str | None = None
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
