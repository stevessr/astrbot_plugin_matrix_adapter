"""
Matrix HTTP Client - VoIP Mixin
Provides VoIP helper methods (TURN server discovery)
"""

from typing import Any


class VoipMixin:
    """VoIP methods for Matrix client"""

    async def get_turn_server(self) -> dict[str, Any]:
        """
        Get TURN server configuration

        Returns:
            TURN server response
        """
        return await self._request("GET", "/_matrix/client/v3/voip/turnServer")
