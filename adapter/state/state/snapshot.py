"""Snapshot serialization for runtime state."""

from typing import Any


class MatrixRuntimeStateSnapshotMixin:
    """Serialize runtime state for reporting."""

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
            "live_message_inbound_count": self.live_message_inbound_count,
            "live_message_inbound_edit_count": self.live_message_inbound_edit_count,
            "live_message_outbound_initial_count": self.live_message_outbound_initial_count,
            "live_message_outbound_edit_count": self.live_message_outbound_edit_count,
            "last_live_message_at": self.last_live_message_at,
            "reconnect_requests": self.reconnect_requests,
            "recent_errors": self.recent_errors(),
        }
