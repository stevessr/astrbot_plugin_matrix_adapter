"""Message deletion and abuse-reporting operations."""


class SenderMediaModerationMixin:
    """Delegate message deletion and reporting."""

    async def delete_message(
        self,
        room_id: str,
        event_id: str,
        reason: str | None = None,
        txn_id: str | None = None,
        *,
        use_legacy_endpoint: bool = False,
    ) -> dict:
        """Delete (redact) a message in a room."""
        return await self.client.redact_event(
            room_id,
            event_id,
            reason=reason,
            txn_id=txn_id,
            use_legacy_endpoint=use_legacy_endpoint,
        )

    async def report_message(
        self,
        room_id: str,
        event_id: str,
        *,
        score: int | None = None,
        reason: str | None = None,
    ) -> dict:
        """Report an abusive Matrix event.

        ``score`` is accepted for source compatibility but is not transmitted on
        Matrix v1.18+, where MSC4277 removed the field.
        """
        return await self.client.report_event(
            room_id=room_id,
            event_id=event_id,
            score=score,
            reason=reason,
        )

    async def report_room(self, room_id: str, reason: str = "") -> dict:
        """Report a Matrix room."""
        return await self.client.report_room(room_id=room_id, reason=reason)

    async def report_user(self, user_id: str, reason: str = "") -> dict:
        """Report a Matrix user."""
        return await self.client.report_user(user_id=user_id, reason=reason)
