"""Matrix room tag retrieval operations."""

from typing import Any

from ..path_utils import quote_path_segment


class TagsReadMixin:
    """Retrieve tags for Matrix rooms."""

    async def get_room_tags(self, room_id: str) -> dict[str, Any]:
        """
        Get tags for a room

        Args:
            room_id: Room ID

        Returns:
            Tags response
        """
        user = quote_path_segment(self.user_id)
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/user/{user}/rooms/{room}/tags"
        return await self._request("GET", endpoint)
