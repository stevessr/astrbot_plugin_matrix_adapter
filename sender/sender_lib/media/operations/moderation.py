"""Message deletion and abuse-reporting operations."""


class SenderMediaModerationMixin:
    """Delegate message deletion and reporting."""

    async def delete_message(
        self,
        room_id: str,
        event_id: str,
        reason: str | None = None,
        txn_id: str | None = None,
    ) -> dict:
        """Delete (redact) a message in a room."""
        return await self.client.redact_event(
            room_id, event_id, reason=reason, txn_id=txn_id
        )

    async def report_message(
        self,
        room_id: str,
        event_id: str,
        *,
        score: int = -100,
        reason: str | None = None,
    ) -> dict:
        """Report an abusive Matrix event."""
        return await self.client.report_event(
            room_id=room_id,
            event_id=event_id,
            score=score,
            reason=reason,
        )
