"""Encrypted message detection for event dispatch."""

from ......constants import M_ROOM_ENCRYPTED


class MatrixEventProcessorMessagesDecryptGuardMixin:
    """Detect encrypted message events."""

    def _is_encrypted_message_event(
        self,
        event_type: str,
        event_content: dict,
    ) -> bool:
        """Return whether the event carries encrypted content."""
        # Check if message is encrypted
        if not (event_type == M_ROOM_ENCRYPTED or event_content.get("algorithm")):
            return False
        return True


__all__ = ["MatrixEventProcessorMessagesDecryptGuardMixin"]
