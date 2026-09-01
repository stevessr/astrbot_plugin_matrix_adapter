"""Room event, state, and search query operations."""

from typing import Any


class SenderRoomQueriesMixin:
    """Delegates room event, state, and search queries."""

    async def get_room_members(self, room_id: str) -> dict:
        """Get Matrix room member events."""
        return await self.client.get_room_members(room_id)

    async def get_room_messages(
        self,
        room_id: str,
        *,
        from_token: str | None = None,
        to_token: str | None = None,
        direction: str = "b",
        limit: int = 10,
    ) -> dict:
        """Paginate Matrix room messages."""
        return await self.client.room_messages(
            room_id=room_id,
            from_token=from_token,
            to_token=to_token,
            direction=direction,
            limit=limit,
        )

    async def get_room_state(self, room_id: str) -> list[dict[str, Any]]:
        """Get full Matrix room state."""
        return await self.client.get_room_state(room_id)

    async def get_room_state_event(
        self,
        room_id: str,
        event_type: str,
        state_key: str = "",
        format: str | None = None,
    ) -> dict:
        """Get state content or, with ``format='event'``, full event metadata."""
        return await self.client.get_room_state_event(
            room_id=room_id,
            event_type=event_type,
            state_key=state_key,
            format=format,
        )

    async def set_room_state_event(
        self,
        room_id: str,
        event_type: str,
        content: dict[str, Any],
        state_key: str = "",
    ) -> dict:
        """Set a generic Matrix room state event."""
        return await self.client.set_room_state_event(
            room_id=room_id,
            event_type=event_type,
            content=content,
            state_key=state_key,
        )

    async def get_event(self, room_id: str, event_id: str) -> dict:
        """Fetch one Matrix event from a room."""
        return await self.client.get_event(room_id=room_id, event_id=event_id)

    async def search_messages(
        self,
        search_term: str,
        *,
        keys: list[str] | None = None,
        filter: dict[str, Any] | None = None,
        order_by: str = "recent",
        event_context: dict[str, Any] | None = None,
    ) -> dict:
        """Search Matrix room events by content."""
        return await self.client.search(
            search_term=search_term,
            keys=keys,
            filter=filter,
            order_by=order_by,
            event_context=event_context,
        )
