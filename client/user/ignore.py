"""Ignored-user account-data operations for the Matrix client."""

from typing import Any

from ..path_utils import quote_path_segment


class UserIgnoreMixin:
    """Read and update the account's ignored-user list."""

    async def get_ignored_users(self) -> list[str]:
        """
        Get list of ignored user IDs

        Returns:
            List of ignored user IDs
        """
        try:
            data = await self.get_global_account_data("m.ignored_user_list")
            ignored = data.get("ignored_users", {})
            return list(ignored.keys())
        except Exception:
            return []

    async def ignore_user(self, user_id: str) -> dict[str, Any]:
        """
        Add a user to the ignore list

        Args:
            user_id: User ID to ignore

        Returns:
            Empty dict on success
        """
        # Get current ignored users
        ignored = await self.get_ignored_users()
        if user_id not in ignored:
            ignored.append(user_id)

        # Build ignored_users dict
        ignored_users = {uid: {} for uid in ignored}

        endpoint = (
            f"/_matrix/client/v3/user/{quote_path_segment(self.user_id)}"
            "/account_data/m.ignored_user_list"
        )
        return await self._request(
            "PUT", endpoint, data={"ignored_users": ignored_users}
        )

    async def unignore_user(self, user_id: str) -> dict[str, Any]:
        """
        Remove a user from the ignore list

        Args:
            user_id: User ID to unignore

        Returns:
            Empty dict on success
        """
        # Get current ignored users
        ignored = await self.get_ignored_users()
        if user_id in ignored:
            ignored.remove(user_id)

        # Build ignored_users dict
        ignored_users = {uid: {} for uid in ignored}

        endpoint = (
            f"/_matrix/client/v3/user/{quote_path_segment(self.user_id)}"
            "/account_data/m.ignored_user_list"
        )
        return await self._request(
            "PUT", endpoint, data={"ignored_users": ignored_users}
        )
