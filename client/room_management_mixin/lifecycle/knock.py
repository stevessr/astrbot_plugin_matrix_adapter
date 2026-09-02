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
        *,
        via: list[str] | None = None,
    ) -> dict[str, Any]:
        """Knock on a room using the stable ``via`` query parameter.

        ``server_name`` remains accepted as a deprecated Python-level alias,
        but Matrix v1.14 removed it from the Client-Server wire format.
        """
        room = quote_path_segment(room_id_or_alias)
        endpoint = f"/_matrix/client/v3/knock/{room}"
        data: dict[str, Any] = {}
        if reason:
            data["reason"] = reason
        selected_via = via if via is not None else server_name
        params: dict[str, Any] = {}
        if selected_via:
            params["via"] = list(dict.fromkeys(selected_via))
        return await self._request("POST", endpoint, data=data, params=params)

    async def accept_knock(
        self, room_id: str, user_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        """Accept a knock request by inviting the user."""
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/invite"
        data: dict[str, Any] = {"user_id": user_id}
        if reason:
            data["reason"] = reason
        return await self._request("POST", endpoint, data=data)

    async def reject_knock(
        self, room_id: str, user_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        """Reject a knock request by kicking the user from knock state."""
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/kick"
        data: dict[str, Any] = {"user_id": user_id}
        if reason:
            data["reason"] = reason
        return await self._request("POST", endpoint, data=data)


__all__ = ["RoomKnockMixin"]
