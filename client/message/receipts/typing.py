"""Matrix room typing status operations."""

from typing import Any

from ....constants import DEFAULT_TIMEOUT_MS_30000
from ...path_utils import quote_path_segment


class MessageTypingMixin:
    async def set_typing(
        self, room_id: str, typing: bool = True, timeout: int = DEFAULT_TIMEOUT_MS_30000
    ) -> dict[str, Any]:
        """
        Set typing status in a room

        Args:
            room_id: Room ID
            typing: Whether the user is typing
            timeout: Typing timeout in milliseconds

        Returns:
            Response data
        """
        room = quote_path_segment(room_id)
        user = quote_path_segment(self.user_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/typing/{user}"
        data = {"typing": typing, "timeout": timeout} if typing else {"typing": False}
        return await self._request("PUT", endpoint, data=data)
