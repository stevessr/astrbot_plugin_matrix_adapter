"""
Matrix HTTP Client - Profile Mixin
Provides user profile and presence methods
"""

from typing import Any

from astrbot.api import logger


class ProfileMixin:
    """Profile and presence methods for Matrix client"""

    async def get_global_account_data(self, type: str) -> dict[str, Any]:
        """
        Get user global account data

        Args:
            type: Account data type (e.g., m.direct)

        Returns:
            Account data content
        """
        # Ensure user_id is set (it should be after login)
        if not hasattr(self, "user_id") or not self.user_id:
            raise Exception("Client not logged in or user_id not set")

        endpoint = f"/_matrix/client/v3/user/{self.user_id}/account_data/{type}"
        try:
            return await self._request("GET", endpoint)
        except Exception:
            # Return empty dict if not found (404)
            return {}

    async def set_display_name(self, display_name: str) -> dict[str, Any]:
        """
        Set user display name

        Args:
            display_name: New display name

        Returns:
            Response data
        """
        endpoint = f"/_matrix/client/v3/profile/{self.user_id}/displayname"
        return await self._request("PUT", endpoint, data={"displayname": display_name})

    async def get_display_name(self, user_id: str) -> str:
        """
        Get user display name

        Args:
            user_id: Matrix user ID

        Returns:
            Display name
        """
        endpoint = f"/_matrix/client/v3/profile/{user_id}/displayname"
        response = await self._request("GET", endpoint, authenticated=False)
        return response.get("displayname", user_id)

    async def get_avatar_url(self, user_id: str) -> str | None:
        """
        Get user avatar URL

        Args:
            user_id: Matrix user ID

        Returns:
            Avatar URL (mxc:// format) or None
        """
        endpoint = f"/_matrix/client/v3/profile/{user_id}/avatar_url"
        try:
            response = await self._request("GET", endpoint, authenticated=False)
            return response.get("avatar_url")
        except Exception:
            return None

    async def set_presence(
        self, status: str = "online", status_msg: str | None = None
    ) -> dict[str, Any]:
        """
        Set user presence status

        Args:
            status: Presence status ('online', 'unavailable', 'offline')
            status_msg: Optional status message

        Returns:
            Empty dict on success
        """
        endpoint = f"/_matrix/client/v3/presence/{self.user_id}/status"
        data: dict[str, Any] = {"presence": status}
        if status_msg:
            data["status_msg"] = status_msg
        return await self._request("PUT", endpoint, data=data)

    async def get_user_room(self, user_id: str) -> str | None:
        """
        Find a direct message room with the specified user

        Args:
            user_id: The user ID to find a DM room for

        Returns:
            The room ID if found, None otherwise
        """
        try:
            # Get direct chat map from account data
            account_data = await self.get_global_account_data("m.direct")
            content = account_data.get("content", {})

            # Look for rooms with this user
            rooms = content.get(user_id, [])
            if rooms and isinstance(rooms, list) and len(rooms) > 0:
                # Return the first room found
                return rooms[0]

            return None
        except Exception as e:
            logger.warning(f"Failed to find DM room for {user_id}: {e}")
            return None
