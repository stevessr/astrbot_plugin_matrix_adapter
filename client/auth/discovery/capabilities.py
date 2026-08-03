"""Matrix client and login capability discovery operations."""

from typing import Any


class AuthDiscoveryCapabilitiesMixin:
    """Discover supported Matrix client and login capabilities."""

    async def get_versions(self) -> dict[str, Any]:
        """
        Get supported Matrix client-server API versions

        Returns:
            Versions response
        """
        return await self._request(
            "GET", "/_matrix/client/versions", authenticated=False
        )

    async def get_capabilities(self) -> dict[str, Any]:
        """
        Get server capabilities

        Returns:
            Capabilities response
        """
        return await self._request("GET", "/_matrix/client/v3/capabilities")

    async def get_login_flows(self) -> dict[str, Any]:
        """
        Get supported login flows from the server

        Returns:
            Response with supported login flows
        """
        return await self._request(
            "GET", "/_matrix/client/v3/login", authenticated=False
        )
