"""Matrix registration-flow discovery operations."""

from typing import Any


class AuthDiscoveryRegistrationMixin:
    """Discover supported Matrix registration capabilities."""

    async def get_register_flows(self) -> dict[str, Any]:
        """
        Get supported registration flows from the server

        Returns:
            Response with supported registration flows
        """
        return await self._request(
            "GET", "/_matrix/client/v3/register", authenticated=False
        )

    async def register_available(self, username: str) -> dict[str, Any]:
        """
        Check if a username is available for registration

        Args:
            username: Desired localpart

        Returns:
            Availability response
        """
        params = {"username": username}
        return await self._request(
            "GET",
            "/_matrix/client/v3/register/available",
            params=params,
            authenticated=False,
        )

    async def register_guest(self) -> dict[str, Any]:
        """
        Register as a guest user

        Returns:
            Guest registration response
        """
        return await self._request(
            "POST",
            "/_matrix/client/v3/register",
            params={"kind": "guest"},
            authenticated=False,
        )
