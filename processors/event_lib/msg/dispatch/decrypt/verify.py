"""Decrypted verification event routing."""

from astrbot.api import logger


class MatrixEventProcessorMessagesDecryptVerifyMixin:
    """Route decrypted verification events to the verification handler."""

    async def _route_decrypted_verification_event(
        self,
        room,
        event,
        sender: str,
        event_content: dict,
        cleartext_relates_to,
    ) -> bool:
        """Handle a decrypted verification event; return True when consumed."""
        # Check if it's from self (same user)
        if sender == self.user_id:
            # Only process if from a different device
            from_device = event.content.get("from_device")
            if (
                from_device
                and self.e2ee_manager
                and from_device == self.e2ee_manager.device_id
            ):
                return True  # Ignore own echo

        logger.debug(f"[EventProcessor] 检测到加密的验证事件 (type={event.event_type})")

        # CRITICAL: For encrypted in-room verification events,
        # m.relates_to is in the CLEARTEXT portion of the encrypted event
        # (event_content), not in the decrypted payload.
        # We need to copy it to the decrypted content for commitment calculation.
        if cleartext_relates_to:
            event.content["m.relates_to"] = cleartext_relates_to

        # Reconstruct event_data for verification handler
        verification_event = {
            "type": event.event_type,
            "sender": sender,
            "event_id": event.event_id,
            "content": event.content,
        }
        await self._handle_in_room_verification(room, verification_event)
        return True


__all__ = ["MatrixEventProcessorMessagesDecryptVerifyMixin"]
