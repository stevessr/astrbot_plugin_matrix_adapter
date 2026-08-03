"""Matrix per-user sync-filter operations."""

from typing import Any

from ...path_utils import quote_path_segment


class AuthSyncFilterMixin:
    """Create and inspect per-user Matrix sync filters."""

    async def create_filter(
        self, user_id: str, filter_data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Create a sync filter for a user

        Args:
            user_id: Matrix user ID
            filter_data: Filter definition

        Returns:
            Response with filter_id
        """
        user = quote_path_segment(user_id)
        endpoint = f"/_matrix/client/v3/user/{user}/filter"
        return await self._request("POST", endpoint, data=filter_data)

    async def get_filter(self, user_id: str, filter_id: str) -> dict[str, Any]:
        """
        Get a sync filter definition

        Args:
            user_id: Matrix user ID
            filter_id: Filter ID

        Returns:
            Filter definition
        """
        user = quote_path_segment(user_id)
        filter_path = quote_path_segment(filter_id)
        endpoint = f"/_matrix/client/v3/user/{user}/filter/{filter_path}"
        return await self._request("GET", endpoint)
