"""Direct-message room creation."""

from typing import Any

from astrbot.api import logger

from ....path_utils import quote_path_segment


class UserRoomCreationDirectMixin:
    """Create direct-message rooms and track m.direct data."""

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
            await self._update_direct_account_data(user_id, room_id)

        return response

    async def _update_direct_account_data(
        self,
        user_id: str,
        room_id: str,
    ) -> None:
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


__all__ = ["UserRoomCreationDirectMixin"]
