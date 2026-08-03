"""Third-party room invitation operations."""

from typing import Any

from ...path_utils import quote_path_segment


class RoomInvitationMixin:
    """Invite third-party identifiers to Matrix rooms."""

    async def invite_3pid(
        self, room_id: str, id_server: str, medium: str, address: str
    ) -> dict[str, Any]:
        """
        Invite a third-party identifier to a room

        Args:
            room_id: Room ID
            id_server: Identity server host
            medium: "email" or "msisdn"
            address: Third-party address

        Returns:
            Response data
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/invite"
        data = {"id_server": id_server, "medium": medium, "address": address}
        return await self._request("POST", endpoint, data=data)
