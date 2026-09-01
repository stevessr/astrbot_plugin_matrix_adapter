"""Matrix client and login capability discovery operations."""

from typing import Any

FORGET_FORCED_UPON_LEAVE_CAPABILITY = "m.forget_forced_upon_leave"
ACCOUNT_MODERATION_CAPABILITY = "m.account_moderation"


class AuthDiscoveryCapabilitiesMixin:
    """Discover supported Matrix client and login capabilities."""

    async def get_versions(self) -> dict[str, Any]:
        """Get supported Matrix client-server API versions."""
        return await self._request(
            "GET", "/_matrix/client/versions", authenticated=False
        )

    async def get_capabilities(self) -> dict[str, Any]:
        """Get server capabilities."""
        return await self._request("GET", "/_matrix/client/v3/capabilities")

    async def is_forget_forced_upon_leave(self) -> bool:
        """Return the Matrix v1.18 forced-forget capability (MSC4267).

        Missing capability data is deliberately treated as ``False`` as required
        by the stable specification.
        """
        response = await self.get_capabilities()
        capabilities = (
            response.get("capabilities", {}) if isinstance(response, dict) else {}
        )
        capability = capabilities.get(FORGET_FORCED_UPON_LEAVE_CAPABILITY, {})
        return isinstance(capability, dict) and capability.get("enabled") is True

    async def get_account_moderation_capability(self) -> dict[str, bool]:
        """Return Matrix v1.18 / MSC4323 account moderation permissions.

        The stable capability is omitted when neither operation is available,
        therefore missing or malformed values safely resolve to ``False``.
        """
        response = await self.get_capabilities()
        capabilities = (
            response.get("capabilities", {}) if isinstance(response, dict) else {}
        )
        capability = capabilities.get(ACCOUNT_MODERATION_CAPABILITY, {})
        if not isinstance(capability, dict):
            capability = {}
        return {
            "lock": capability.get("lock") is True,
            "suspend": capability.get("suspend") is True,
        }

    async def get_login_flows(self) -> dict[str, Any]:
        """Get supported login flows from the server."""
        return await self._request(
            "GET", "/_matrix/client/v3/login", authenticated=False
        )
