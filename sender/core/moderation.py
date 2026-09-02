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

    async def paginate_message_context(
        self,
        room_id: str,
        context: dict[str, Any],
        *,
        direction: str = "b",
        limit: int = 10,
    ) -> dict:
        """Continue pagination from a ``GET /context`` response.

        Matrix v1.19 clarifies that ``context.start`` is the token for
        backwards pagination and ``context.end`` is the token for forwards
        pagination using ``GET /rooms/{roomId}/messages``.
        """
        if direction not in {"b", "f"}:
            raise ValueError("direction must be 'b' (backwards) or 'f' (forwards)")
        if not isinstance(context, dict):
            raise TypeError("context must be a Matrix event-context response")

        token_key = "start" if direction == "b" else "end"
        token = context.get(token_key)
        if not isinstance(token, str) or not token:
            raise ValueError(f"context response has no usable {token_key!r} token")

        return await self.client.room_messages(
            room_id=room_id,
            from_token=token,
            direction=direction,
            limit=limit,
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
