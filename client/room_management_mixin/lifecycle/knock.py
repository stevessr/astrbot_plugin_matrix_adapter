"""Room knock management operations."""

from typing import Any

from ...path_utils import quote_path_segment


class RoomKnockMixin:
    """Manage room knock requests."""

    async def knock_room(
        self,
        room_id_or_alias: str,
        reason: str | None = None,
        server_name: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Knock on a room (if supported by server)

        Args:
            room_id_or_alias: Room ID or alias
            reason: Optional reason
            server_name: Optional list of server names to try knocking via
                (MSC3881 remote room joining, mirrors ``/join`` behaviour)

        Returns:
            Knock response with room_id
        """
        room = quote_path_segment(room_id_or_alias)
        endpoint = f"/_matrix/client/v3/knock/{room}"
        data: dict[str, Any] = {}
        if reason:
            data["reason"] = reason
        if server_name:
            data["server_name"] = list(server_name)
        return await self._request("POST", endpoint, data=data)

    async def accept_knock(
        self, room_id: str, user_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        """
        Accept a knock request by inviting the user

        According to Matrix spec, accepting a knock is done by inviting the user.

        Args:
            room_id: Room ID
            user_id: User ID who knocked
            reason: Optional reason for the invite

        Returns:
            Empty dict on success
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/invite"
        data: dict[str, Any] = {"user_id": user_id}
        if reason:
            data["reason"] = reason
        return await self._request("POST", endpoint, data=data)

    async def reject_knock(
        self, room_id: str, user_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        """
        Reject a knock request by kicking the user from knock state

        According to Matrix spec, rejecting a knock is done by changing the
        user's membership from 'knock' to 'leave' via kick.

        Args:
            room_id: Room ID
            user_id: User ID who knocked
            reason: Optional reason for rejection

        Returns:
            Empty dict on success
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/kick"
        data: dict[str, Any] = {"user_id": user_id}
        if reason:
            data["reason"] = reason
        return await self._request("POST", endpoint, data=data)


__all__ = ["RoomKnockMixin"]
