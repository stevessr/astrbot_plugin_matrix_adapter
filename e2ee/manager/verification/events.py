"""Delegation from the E2EE manager to SAS verification handlers."""


class E2EEManagerVerificationEventsMixin:
    """将验证事件转发给 SASVerification 实例。"""

    async def handle_verification_event(
        self, event_type: str, sender: str, content: dict
    ) -> bool:
        """Handle verification events (m.key.verification.*)."""
        if self._verification:
            return await self._verification.handle_verification_event(
                event_type, sender, content
            )
        return False

    async def handle_in_room_verification_event(
        self,
        event_type: str,
        sender: str,
        content: dict,
        room_id: str,
        event_id: str,
    ) -> bool:
        """Handle in-room verification events."""
        if self._verification:
            return await self._verification.handle_in_room_verification_event(
                event_type, sender, content, room_id, event_id
            )
        return False


__all__ = ["E2EEManagerVerificationEventsMixin"]
