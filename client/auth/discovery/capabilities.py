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

    async def get_msc4357_server_advertisement(self) -> bool | None:
        """Read an optional homeserver advertisement for MSC4357.

        MSC4357 itself currently defines no mandatory ``/versions`` feature
        flag because Live Messages need no new server endpoint. Some servers
        may still publish the conventional ``org.matrix.msc4357`` flag (or its
        ``.stable`` companion). Treat those flags as advisory only: ``None``
        means "not advertised", not "unsupported".
        """

        versions = await self.get_versions()
        unstable = (
            versions.get("unstable_features", {})
            if isinstance(versions, dict)
            else {}
        )
        if not isinstance(unstable, dict):
            return None

        # Prefer a stable-advertisement hint if an implementation exposes one.
        for feature in ("org.matrix.msc4357.stable", "org.matrix.msc4357"):
            value = unstable.get(feature)
            if isinstance(value, bool):
                return value
        return None

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
