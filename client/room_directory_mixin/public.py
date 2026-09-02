"""Matrix public-room listing and visibility operations."""

from typing import Any

from ..path_utils import quote_path_segment


class RoomPublicDirectoryMixin:
    """List public rooms and manage room directory visibility."""

    async def list_public_rooms(
        self,
        server: str | None = None,
        limit: int | None = None,
        since: str | None = None,
        filter: dict[str, Any] | None = None,
        room_types: list[str | None] | None = None,
    ) -> dict[str, Any]:
        """List public rooms using the stable GET/POST wire shapes.

        Matrix v1.4 / MSC3827 adds ``filter.room_types`` to the POST form. A
        ``None`` entry explicitly includes rooms which have no room type. The
        remote ``server`` selector is a query parameter for *both* GET and POST;
        it is never part of the POST JSON body.
        """
        endpoint = "/_matrix/client/v3/publicRooms"
        params: dict[str, Any] = {}
        if server:
            params["server"] = server

        if filter is not None and not isinstance(filter, dict):
            raise ValueError("filter must be a dict when provided")
        if room_types is not None:
            if not isinstance(room_types, list) or not all(
                value is None or isinstance(value, str) for value in room_types
            ):
                raise ValueError("room_types must be a list of strings or None")

        use_post = filter is not None or room_types is not None
        if not use_post:
            if limit is not None:
                params["limit"] = limit
            if since:
                params["since"] = since
            return await self._request("GET", endpoint, params=params)

        effective_filter = dict(filter or {})
        if room_types is not None:
            effective_filter["room_types"] = list(room_types)

        data: dict[str, Any] = {"filter": effective_filter}
        if limit is not None:
            data["limit"] = limit
        if since:
            data["since"] = since
        return await self._request("POST", endpoint, params=params, data=data)

    async def get_room_visibility(self, room_id: str) -> dict[str, Any]:
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/directory/list/room/{room}"
        return await self._request("GET", endpoint)

    async def set_room_visibility(
        self, room_id: str, visibility: str
    ) -> dict[str, Any]:
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/directory/list/room/{room}"
        return await self._request("PUT", endpoint, data={"visibility": visibility})
