"""Adapter runtime status and reconnect operations."""

from ...utils.utils import mask_device_id


class MatrixAdapterRuntimeStatusMixin:
    """Expose runtime health and reconnect state."""

    _mask_device_id = staticmethod(mask_device_id)

    async def _on_sync_response(self, sync_response: dict) -> None:
        runtime_state = getattr(self, "runtime_state", None)
        if runtime_state:
            runtime_state.mark_sync_ok()

    def get_runtime_status(self) -> dict:
        runtime_state = getattr(self, "runtime_state", None)
        sync_manager = getattr(self, "sync_manager", None)
        outbound_tracker = getattr(self, "outbound_tracker", None)
        client = getattr(self, "client", None)
        matrix_config = getattr(self, "_matrix_config", None)
        status = runtime_state.snapshot() if runtime_state else {}
        if matrix_config:
            status.update(
                {
                    "homeserver": matrix_config.homeserver,
                    "user_id": matrix_config.user_id,
                    "device_id_masked": self._mask_device_id(
                        getattr(client, "device_id", None) or matrix_config.device_id
                    ),
                    "auth_method": matrix_config.auth_method,
                    "e2ee_enabled": bool(getattr(self, "e2ee_manager", None)),
                }
            )
        if sync_manager and hasattr(sync_manager, "status_snapshot"):
            status["sync"] = sync_manager.status_snapshot()
            if not status.get("last_error_message"):
                status["last_error_message"] = status["sync"].get("last_sync_error")
                if status.get("last_error_message") and not status.get(
                    "last_error_category"
                ):
                    status["last_error_category"] = "sync"
        if outbound_tracker:
            status["outbound"] = outbound_tracker.summary()
            status["outbound_recent"] = outbound_tracker.list_records(limit=5)
        return status

    def request_reconnect(self) -> bool:
        runtime_state = getattr(self, "runtime_state", None)
        if runtime_state:
            runtime_state.mark_reconnect_requested()
        sync_manager = getattr(self, "sync_manager", None)
        if sync_manager and hasattr(sync_manager, "request_reconnect"):
            return bool(sync_manager.request_reconnect())
        return False
