"""
Matrix HTTP Client - Third-Party Mixin
Provides third-party protocol lookup methods
"""

from typing import Any


class ThirdPartyMixin:
    """Third-party protocol lookup methods for Matrix client"""

    async def get_thirdparty_protocols(self) -> dict[str, Any]:
        """
        Get supported third-party protocols

        Returns:
            Protocols response
        """
        return await self._request("GET", "/_matrix/client/v3/thirdparty/protocols")

    async def get_thirdparty_protocol(self, protocol: str) -> dict[str, Any]:
        """
        Get details for a third-party protocol

        Args:
            protocol: Protocol name

        Returns:
            Protocol response
        """
        endpoint = f"/_matrix/client/v3/thirdparty/protocol/{protocol}"
        return await self._request("GET", endpoint)

    async def get_thirdparty_location(
        self, protocol: str, fields: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        Query third-party locations

        Args:
            protocol: Protocol name
            fields: Fields to match

        Returns:
            List of locations
        """
        endpoint = f"/_matrix/client/v3/thirdparty/location/{protocol}"
        return await self._request("GET", endpoint, params=fields)

    async def get_thirdparty_user(
        self, protocol: str, fields: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        Query third-party users

        Args:
            protocol: Protocol name
            fields: Fields to match

        Returns:
            List of users
        """
        endpoint = f"/_matrix/client/v3/thirdparty/user/{protocol}"
        return await self._request("GET", endpoint, params=fields)
