"""Matrix room tag mutation operations."""

from typing import Any

from ..path_utils import quote_path_segment


class TagsMutationMixin:
    """Set and delete tags for Matrix rooms."""

    async def set_room_tag(
        self, room_id: str, tag: str, content: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Set a tag for a room

        Args:
            room_id: Room ID
            tag: Tag name (e.g., m.favourite)
            content: Optional tag content

        Returns:
            Empty dict on success
        """
        user = quote_path_segment(self.user_id)
        room = quote_path_segment(room_id)
        tag_name = quote_path_segment(tag)
        endpoint = f"/_matrix/client/v3/user/{user}/rooms/{room}/tags/{tag_name}"
        return await self._request("PUT", endpoint, data=content or {})

    async def delete_room_tag(self, room_id: str, tag: str) -> dict[str, Any]:
        """
        Delete a tag for a room

        Args:
            room_id: Room ID
            tag: Tag name

        Returns:
            Empty dict on success
        """
        user = quote_path_segment(self.user_id)
        room = quote_path_segment(room_id)
        tag_name = quote_path_segment(tag)
        endpoint = f"/_matrix/client/v3/user/{user}/rooms/{room}/tags/{tag_name}"
        return await self._request("DELETE", endpoint)
