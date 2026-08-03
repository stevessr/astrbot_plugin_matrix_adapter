"""Matrix room alias and room-alias listing operations."""

from typing import Any

from ..path_utils import quote_path_segment


class RoomAliasMixin:
    """Create, delete, resolve, and list room aliases."""

    async def create_room_alias(self, room_alias: str, room_id: str) -> dict[str, Any]:
        """
        Create or update a room alias

        Args:
            room_alias: Room alias (e.g., #alias:example.com)
            room_id: Room ID

        Returns:
            Empty dict on success
        """
        alias = quote_path_segment(room_alias)
        endpoint = f"/_matrix/client/v3/directory/room/{alias}"
        return await self._request("PUT", endpoint, data={"room_id": room_id})

    async def delete_room_alias(self, room_alias: str) -> dict[str, Any]:
        """
        Delete a room alias

        Args:
            room_alias: Room alias (e.g., #alias:example.com)

        Returns:
            Empty dict on success
        """
        alias = quote_path_segment(room_alias)
        endpoint = f"/_matrix/client/v3/directory/room/{alias}"
        return await self._request("DELETE", endpoint)

    async def get_room_alias(self, room_alias: str) -> dict[str, Any]:
        """
        Resolve a room alias

        Args:
            room_alias: Room alias (e.g., #alias:example.com)

        Returns:
            Dict containing room_id and servers
        """
        alias = quote_path_segment(room_alias)
        endpoint = f"/_matrix/client/v3/directory/room/{alias}"
        return await self._request("GET", endpoint)

    async def get_room_aliases(self, room_id: str) -> dict[str, Any]:
        """
        Get aliases for a room

        Args:
            room_id: Room ID

        Returns:
            Response containing aliases
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/aliases"
        return await self._request("GET", endpoint)
