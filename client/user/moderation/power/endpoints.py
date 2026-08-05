"""Room power-level endpoint operations."""

from typing import Any

from ....path_utils import quote_path_segment


class UserPowerLevelEndpointMixin:
    """Raw m.room.power_levels state operations."""

    async def get_power_levels(self, room_id: str) -> dict[str, Any]:
        """
        Get power levels for a room

        Args:
            room_id: Room ID

        Returns:
            Power levels state event content
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/state/m.room.power_levels/"
        return await self._request("GET", endpoint)

    async def set_power_levels(
        self, room_id: str, power_levels: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Set power levels for a room

        Args:
            room_id: Room ID
            power_levels: Power levels content

        Returns:
            Response with event_id
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/state/m.room.power_levels/"
        return await self._request("PUT", endpoint, data=power_levels)


__all__ = ["UserPowerLevelEndpointMixin"]
