"""Room alias delegation operations."""


class SenderRoomAliasesMixin:
    """Delegate room alias operations to the client."""

    async def create_room_alias(self, room_alias: str, room_id: str) -> dict:
        """Create or update a Matrix room alias."""
        return await self.client.create_room_alias(
            room_alias=room_alias,
            room_id=room_id,
        )

    async def delete_room_alias(self, room_alias: str) -> dict:
        """Delete a Matrix room alias."""
        return await self.client.delete_room_alias(room_alias)

    async def get_room_alias(self, room_alias: str) -> dict:
        """Resolve a Matrix room alias to its room ID and servers."""
        return await self.client.get_room_alias(room_alias)

    async def get_room_aliases(self, room_id: str) -> dict:
        """Get aliases associated with a Matrix room."""
        return await self.client.get_room_aliases(room_id)
