"""Matrix third-party protocol discovery operations."""

from typing import Any


class ThirdPartyProtocolMixin:
    """Discover supported third-party protocols."""

    async def get_thirdparty_protocols(self) -> dict[str, Any]:
        """
        Get supported third-party protocols

        Returns:
            Protocols response
        """
        return await self._request("GET", "/_matrix/client/v3/thirdparty/protocols")
