"""
Matrix HTTP Client - Profile Account Mixin
Provides account data and profile methods
"""

from typing import Any

from astrbot.api import logger

from ...constants import M_MARKED_UNREAD, MSC2867_MARKED_UNREAD
from ..path_utils import quote_path_segment


class ProfileAccountMixin:
    """Account data and user profile methods for Matrix client"""

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

        user = quote_path_segment(self.user_id)
        data_type = quote_path_segment(type)
        endpoint = f"/_matrix/client/v3/user/{user}/account_data/{data_type}"
        try:
            return await self._request("GET", endpoint)
        except Exception:
            # Return empty dict if not found (404)
            return {}

    async def set_global_account_data(
        self, type: str, content: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Set user global account data

        Args:
            type: Account data type (e.g., m.direct)
            content: Account data content

        Returns:
            Empty dict on success
        """
        if not hasattr(self, "user_id") or not self.user_id:
            raise Exception("Client not logged in or user_id not set")
        user = quote_path_segment(self.user_id)
        data_type = quote_path_segment(type)
        endpoint = f"/_matrix/client/v3/user/{user}/account_data/{data_type}"
        return await self._request("PUT", endpoint, data=content)

    async def get_room_account_data(self, room_id: str, type: str) -> dict[str, Any]:
        """
        Get room account data for current user

        Args:
            room_id: Room ID
            type: Account data type

        Returns:
            Account data content
        """
        if not hasattr(self, "user_id") or not self.user_id:
            raise Exception("Client not logged in or user_id not set")
        user = quote_path_segment(self.user_id)
        room = quote_path_segment(room_id)
        data_type = quote_path_segment(type)
        endpoint = f"/_matrix/client/v3/user/{user}/rooms/{room}/account_data/{data_type}"
        try:
            return await self._request("GET", endpoint)
        except Exception:
            return {}

    async def set_room_account_data(
        self, room_id: str, type: str, content: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Set room account data for current user

        Args:
            room_id: Room ID
            type: Account data type
            content: Account data content

        Returns:
            Empty dict on success
        """
        if not hasattr(self, "user_id") or not self.user_id:
            raise Exception("Client not logged in or user_id not set")
        user = quote_path_segment(self.user_id)
        room = quote_path_segment(room_id)
        data_type = quote_path_segment(type)
        endpoint = f"/_matrix/client/v3/user/{user}/rooms/{room}/account_data/{data_type}"
        return await self._request("PUT", endpoint, data=content)

    async def set_display_name(self, display_name: str) -> dict[str, Any]:
        """
        Set user display name

        Args:
            display_name: New display name

        Returns:
            Response data
        """
        user = quote_path_segment(self.user_id)
        endpoint = f"/_matrix/client/v3/profile/{user}/displayname"
        return await self._request("PUT", endpoint, data={"displayname": display_name})

    async def get_display_name(self, user_id: str) -> str:
        """
        Get user display name

        Args:
            user_id: Matrix user ID

        Returns:
            Display name
        """
        user = quote_path_segment(user_id)
        endpoint = f"/_matrix/client/v3/profile/{user}/displayname"
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
        user = quote_path_segment(user_id)
        endpoint = f"/_matrix/client/v3/profile/{user}/avatar_url"
        try:
            response = await self._request("GET", endpoint, authenticated=False)
            return response.get("avatar_url")
        except Exception:
            return None

    async def set_avatar_url(self, avatar_url: str) -> dict[str, Any]:
        """
        Set user avatar URL

        Args:
            avatar_url: New avatar URL (mxc:// format)

        Returns:
            Response data
        """
        user = quote_path_segment(self.user_id)
        endpoint = f"/_matrix/client/v3/profile/{user}/avatar_url"
        return await self._request("PUT", endpoint, data={"avatar_url": avatar_url})

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
            if isinstance(rooms, list):
                for room_id in rooms:
                    room_id_text = str(room_id or "").strip()
                    if room_id_text:
                        return room_id_text

            return None
        except Exception as e:
            logger.warning(f"Failed to find DM room for {user_id}: {e}")
            return None

    async def set_room_marked_unread(
        self, room_id: str, unread: bool = True
    ) -> dict[str, Any]:
        """
        Mark a room as (un)read on the user's account (MSC2867).

        Writes both the stable ``m.marked_unread`` key (Matrix v1.12+) and the
        legacy ``com.famedly.marked_unread`` key for older clients/servers.
        """
        content = {"unread": bool(unread)}
        # Stable key (room account data)
        await self.set_room_account_data(room_id, M_MARKED_UNREAD, content)
        # Legacy unstable key for older clients
        try:
            await self.set_room_account_data(
                room_id, MSC2867_MARKED_UNREAD, content
            )
        except Exception as e:
            logger.debug(f"Failed to set legacy marked_unread: {e}")
        return content

    async def get_room_marked_unread(self, room_id: str) -> bool:
        """Read the marked-unread state of a room (MSC2867)."""
        for type_key in (M_MARKED_UNREAD, MSC2867_MARKED_UNREAD):
            try:
                data = await self.get_room_account_data(room_id, type_key)
            except Exception:
                continue
            content = data.get("content") if isinstance(data, dict) else None
            if isinstance(content, dict) and "unread" in content:
                return bool(content.get("unread"))
            if isinstance(data, dict) and "unread" in data:
                return bool(data.get("unread"))
        return False
