"""Room directory and visibility delegation operations."""

from typing import Any


class SenderRoomDirectoryMixin:
    """Delegate public-room directory operations to the client."""

    async def list_public_rooms(
        self,
        *,
        server: str | None = None,
        limit: int | None = None,
        since: str | None = None,
        filter: dict[str, Any] | None = None,
        room_types: list[str | None] | None = None,
    ) -> dict:
        """List Matrix public rooms, optionally filtering by room type."""
        return await self.client.list_public_rooms(
            server=server,
            limit=limit,
            since=since,
            filter=filter,
            room_types=room_types,
        )

    async def get_room_visibility(self, room_id: str) -> dict:
        return await self.client.get_room_visibility(room_id)

    async def set_room_visibility(self, room_id: str, visibility: str) -> dict:
        return await self.client.set_room_visibility(
            room_id=room_id,
            visibility=visibility,
        )
