"""Matrix logout and access-token refresh operations."""

from typing import Any


class AuthSessionLifecycleMixin:
    """End Matrix sessions and refresh access tokens."""

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
