"""Matrix session restoration and identity operations."""

from typing import Any


class AuthSessionIdentityMixin:
    """Restore sessions and inspect the current Matrix identity."""

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
