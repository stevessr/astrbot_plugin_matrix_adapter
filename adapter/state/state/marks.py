"""State mark helpers for runtime state."""

from ..time import _utc_now_iso


class MatrixRuntimeStateMarksMixin:
    """Update individual runtime state fields."""

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

    def mark_live_message_inbound(self, *, is_edit: bool = False) -> None:
        self.live_message_inbound_count += 1
        if is_edit:
            self.live_message_inbound_edit_count += 1
        self.last_live_message_at = _utc_now_iso()

    def mark_live_message_outbound_initial(self) -> None:
        self.live_message_outbound_initial_count += 1
        self.last_live_message_at = _utc_now_iso()

    def mark_live_message_outbound_edit(self) -> None:
        self.live_message_outbound_edit_count += 1
        self.last_live_message_at = _utc_now_iso()

    def mark_presence_updated(self) -> None:
        self.last_presence_update_at = _utc_now_iso()

    def mark_reconnect_requested(self) -> None:
        self.reconnect_requests += 1
        self.last_reconnect_request_at = _utc_now_iso()
