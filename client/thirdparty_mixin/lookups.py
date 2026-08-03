"""Matrix third-party location and user lookup operations."""

from typing import Any

from ..path_utils import quote_path_segment


class ThirdPartyLookupMixin:
    """Query third-party locations and users."""

    async def get_thirdparty_protocol(self, protocol: str) -> dict[str, Any]:
        """
        Get details for a third-party protocol

        Args:
            protocol: Protocol name

        Returns:
            Protocol response
        """
        protocol_path = quote_path_segment(protocol)
        endpoint = f"/_matrix/client/v3/thirdparty/protocol/{protocol_path}"
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
        protocol_path = quote_path_segment(protocol)
        endpoint = f"/_matrix/client/v3/thirdparty/location/{protocol_path}"
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
        protocol_path = quote_path_segment(protocol)
        endpoint = f"/_matrix/client/v3/thirdparty/user/{protocol_path}"
        return await self._request("GET", endpoint, params=fields)
