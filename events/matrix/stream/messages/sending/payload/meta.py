"""Live message tracker metadata construction."""


class MatrixPlatformEventMessagesPayloadMetaMixin:
    """Build live-message tracker metadata."""

    def _build_live_tracker_metadata(
        self,
        final: bool,
        current_event_id: str | None,
    ) -> dict:
        """Build tracker metadata for the live message phase."""
        tracker_metadata = {
            "proposal": "msc4357-live-messages",
            "live_message": True,
            "phase": "final"
            if final
            else ("initial" if current_event_id is None else "edit"),
        }
        return tracker_metadata


__all__ = ["MatrixPlatformEventMessagesPayloadMetaMixin"]
