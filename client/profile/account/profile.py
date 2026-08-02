"""Matrix display-name and avatar profile operations."""

from typing import Any

from ...path_utils import quote_path_segment


class ProfileUserMixin:
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
