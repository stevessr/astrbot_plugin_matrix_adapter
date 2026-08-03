"""Direct-message and general room creation operations."""

from typing import Any

from astrbot.api import logger

from ...path_utils import quote_path_segment


class UserRoomCreationMixin:
    """Create direct-message and general Matrix rooms."""

    async def create_dm_room(
        self, user_id: str, name: str | None = None
    ) -> dict[str, Any]:
        """
        Create a direct message room with a user

        Args:
            user_id: User ID to create DM with
            name: Optional room name

        Returns:
            Response with room_id
        """
        data: dict[str, Any] = {
            "invite": [user_id],
            "is_direct": True,
            "preset": "trusted_private_chat",
        }
        if name:
            data["name"] = name

        endpoint = "/_matrix/client/v3/createRoom"
        response = await self._request("POST", endpoint, data=data)

        # Update m.direct account data
        room_id = response.get("room_id")
        if room_id:
            try:
                direct_data = await self.get_global_account_data("m.direct")
                if user_id not in direct_data:
                    direct_data[user_id] = []
                if room_id not in direct_data[user_id]:
                    direct_data[user_id].append(room_id)

                endpoint = (
                    f"/_matrix/client/v3/user/{quote_path_segment(self.user_id)}"
                    "/account_data/m.direct"
                )
                await self._request("PUT", endpoint, data=direct_data)
            except Exception as e:
                logger.debug(f"Failed to update m.direct: {e}")

        return response

    async def create_room(
        self,
        name: str | None = None,
        topic: str | None = None,
        invite: list[str] | None = None,
        is_public: bool = False,
        preset: str | None = None,
        creation_content: dict[str, Any] | None = None,
        initial_state: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Create a new room

        Args:
            name: Room name
            topic: Room topic
            invite: List of user IDs to invite
            is_public: Whether room is public
            preset: Room preset (private_chat, public_chat, trusted_private_chat)
            creation_content: Room creation_content payload
            initial_state: Room initial_state payload

        Returns:
            Response with room_id
        """
        data: dict[str, Any] = {}

        if name:
            data["name"] = name
        if topic:
            data["topic"] = topic
        if invite:
            data["invite"] = invite
        if preset:
            data["preset"] = preset
        else:
            data["preset"] = "public_chat" if is_public else "private_chat"

        if is_public:
            data["visibility"] = "public"

        if creation_content and isinstance(creation_content, dict):
            data["creation_content"] = creation_content

        if initial_state and isinstance(initial_state, list):
            data["initial_state"] = initial_state

        endpoint = "/_matrix/client/v3/createRoom"
        return await self._request("POST", endpoint, data=data)
