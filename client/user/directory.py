"""User profile and directory operations for the Matrix client."""

from typing import Any

from astrbot.api import logger

from ..path_utils import quote_path_segment


class UserDirectoryMixin:
    """Profile lookup and user-directory operations."""

    async def get_user_profile(self, user_id: str) -> dict[str, Any]:
        """
        Get full profile for a user

        Args:
            user_id: User ID

        Returns:
            Profile data including displayname and avatar_url
        """
        user = quote_path_segment(user_id)
        endpoint = f"/_matrix/client/v3/profile/{user}"
        try:
            return await self._request("GET", endpoint, authenticated=False)
        except Exception as e:
            logger.debug(f"Failed to get profile for {user_id}: {e}")
            return {}

    # ========== User Search ==========

    async def search_users(self, search_term: str, limit: int = 10) -> dict[str, Any]:
        """
        Search for users on the homeserver

        Args:
            search_term: Search term
            limit: Maximum number of results

        Returns:
            Search results with user list
        """
        endpoint = "/_matrix/client/v3/user_directory/search"
        data = {"search_term": search_term, "limit": limit}
        return await self._request("POST", endpoint, data=data)
