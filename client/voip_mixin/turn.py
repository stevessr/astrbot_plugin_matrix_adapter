"""Matrix TURN server discovery operations."""

from typing import Any


class VoipTurnMixin:
    """Discover TURN server configuration for Matrix VoIP."""

    async def get_turn_server(self) -> dict[str, Any]:
        """
        Get TURN server configuration

        Returns:
            TURN server response
        """
        return await self._request("GET", "/_matrix/client/v3/voip/turnServer")
