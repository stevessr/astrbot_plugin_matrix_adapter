"""
Matrix HTTP Client - Profile Mixin
Provides user profile and presence methods
"""

from typing import Any

from astrbot.api import logger

from ..constants import (
    M_MARKED_UNREAD,
    MSC2867_MARKED_UNREAD,
    MSC4133_PROFILE_PATH,
)
from .path_utils import quote_path_segment


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

    async def set_presence(
        self,
        status: str = "online",
        status_msg: str | None = None,
        last_active_ts: int | None = None,
        currently_active: bool | None = None,
    ) -> dict[str, Any]:
        """
        Set user presence status

        Args:
            status: Presence status ('online', 'unavailable', 'offline')
            status_msg: Optional status message
            last_active_ts: Optional last active timestamp (ms)
            currently_active: Optional active flag

        Returns:
            Empty dict on success
        """
        user = quote_path_segment(self.user_id)
        endpoint = f"/_matrix/client/v3/presence/{user}/status"
        data: dict[str, Any] = {"presence": status}
        if status_msg:
            data["status_msg"] = status_msg
        if last_active_ts is not None:
            data["last_active_ts"] = last_active_ts
        if currently_active is not None:
            data["currently_active"] = currently_active
        return await self._request("PUT", endpoint, data=data)

    async def get_presence(self, user_id: str) -> dict[str, Any]:
        """
        Get user presence status

        Args:
            user_id: Matrix user ID

        Returns:
            Presence response
        """
        user = quote_path_segment(user_id)
        endpoint = f"/_matrix/client/v3/presence/{user}/status"
        return await self._request("GET", endpoint)

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

    async def get_extended_profile(
        self, user_id: str | None = None
    ) -> dict[str, Any]:
        """
        Fetch the full extended profile for a user (MSC4133).

        Falls back to the stable C-S ``/profile/{user_id}`` endpoint if the
        unstable MSC4133 endpoint is unavailable.
        """
        target = user_id or self.user_id
        if not target:
            raise Exception("user_id is required for get_extended_profile")
        try:
            encoded_target = quote_path_segment(target)
            return await self._request(
                "GET",
                f"{MSC4133_PROFILE_PATH}/{encoded_target}",
                authenticated=False,
            )
        except Exception:
            encoded_target = quote_path_segment(target)
            return await self._request(
                "GET",
                f"/_matrix/client/v3/profile/{encoded_target}",
                authenticated=False,
            )

    async def set_extended_profile_field(
        self, field: str, value: Any
    ) -> dict[str, Any]:
        """Set a single extended profile field (MSC4133)."""
        if not field:
            raise ValueError("field is required")
        user = quote_path_segment(self.user_id)
        profile_field = quote_path_segment(field)
        endpoint = f"{MSC4133_PROFILE_PATH}/{user}/{profile_field}"
        return await self._request("PUT", endpoint, data={field: value})

    async def delete_extended_profile_field(self, field: str) -> dict[str, Any]:
        """Remove a single extended profile field (MSC4133)."""
        if not field:
            raise ValueError("field is required")
        user = quote_path_segment(self.user_id)
        profile_field = quote_path_segment(field)
        endpoint = f"{MSC4133_PROFILE_PATH}/{user}/{profile_field}"
        return await self._request("DELETE", endpoint)
