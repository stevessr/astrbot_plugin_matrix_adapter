"""Matrix global and room account-data operations."""

from typing import Any

from ...path_utils import quote_path_segment


class ProfileAccountDataMixin:
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
        endpoint = (
            f"/_matrix/client/v3/user/{user}/rooms/{room}/account_data/{data_type}"
        )
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
        endpoint = (
            f"/_matrix/client/v3/user/{user}/rooms/{room}/account_data/{data_type}"
        )
        return await self._request("PUT", endpoint, data=content)
