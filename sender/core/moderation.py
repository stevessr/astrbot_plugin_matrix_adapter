"""Sender moderation and event-context operations."""

from typing import Any


class SenderModerationMixin:
    async def get_message_context(
        self,
        room_id: str,
        event_id: str,
        *,
        limit: int | None = None,
        filter: dict[str, Any] | None = None,
    ) -> dict:
        """Get events before/after a Matrix event."""
        return await self.client.get_event_context(
            room_id=room_id,
            event_id=event_id,
            limit=limit,
            filter=filter,
        )

    async def promote_to_moderator(self, room_id: str, user_id: str) -> dict:
        """Promote a Matrix user to moderator (power level 50)."""
        return await self.client.promote_to_moderator(
            room_id=room_id,
            user_id=user_id,
        )

    async def demote_user(self, room_id: str, user_id: str) -> dict:
        """Demote a Matrix user to the room default power level."""
        return await self.client.demote_user(room_id=room_id, user_id=user_id)


__all__ = ["SenderModerationMixin"]
