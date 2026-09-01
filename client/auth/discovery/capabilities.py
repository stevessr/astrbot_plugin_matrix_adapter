"""Matrix client and login capability discovery operations."""

from typing import Any

FORGET_FORCED_UPON_LEAVE_CAPABILITY = "m.forget_forced_upon_leave"


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

    async def is_forget_forced_upon_leave(self) -> bool:
        """Return the Matrix v1.18 forced-forget capability (MSC4267).

        Missing capability data is deliberately treated as ``False`` as required
        by the stable specification.
        """
        response = await self.get_capabilities()
        capabilities = response.get("capabilities", {}) if isinstance(response, dict) else {}
        capability = capabilities.get(FORGET_FORCED_UPON_LEAVE_CAPABILITY, {})
        return isinstance(capability, dict) and capability.get("enabled") is True

    async def get_login_flows(self) -> dict[str, Any]:
        """
        Get supported login flows from the server

        Returns:
            Response with supported login flows
        """
        return await self._request(
            "GET", "/_matrix/client/v3/login", authenticated=False
        )
