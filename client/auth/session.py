"""Logout, session restoration, identity, and token refresh operations."""

from typing import Any


class AuthSessionMixin:
    """Manage the currently authenticated Matrix session."""

    async def logout(self) -> dict[str, Any]:
        """
        Logout the current device

        Returns:
            Empty dict on success
        """
        return await self._request("POST", "/_matrix/client/v3/logout")

    async def logout_all(self) -> dict[str, Any]:
        """
        Logout all devices

        Returns:
            Empty dict on success
        """
        return await self._request("POST", "/_matrix/client/v3/logout/all")

    def restore_login(
        self, user_id: str, access_token: str, device_id: str | None = None
    ):
        """
        Restore login session with access token

        Args:
            user_id: Matrix user ID
            access_token: Access token from previous login
            device_id: Device ID (optional)
        """
        self.user_id = user_id
        self.access_token = access_token
        self.device_id = device_id

    async def whoami(self) -> dict[str, Any]:
        """
        Get information about the current user

        Returns:
            User information including user_id and device_id
        """
        return await self._request("GET", "/_matrix/client/v3/account/whoami")

    async def refresh_access_token(self, refresh_token: str) -> dict[str, Any]:
        """
        Refresh access token using a refresh token

        Args:
            refresh_token: Refresh token from previous login

        Returns:
            Response with new access_token and optionally a new refresh_token
        """
        endpoint = "/_matrix/client/v3/refresh"
        data = {"refresh_token": refresh_token}

        response = await self._request("POST", endpoint, data=data, authenticated=False)

        # Update client with new access token
        if "access_token" in response:
            self.access_token = response["access_token"]

        return response
