"""Event context and relation query operations."""

import json
from typing import Any

from ....path_utils import quote_path_segment


class MessageEventQueryMixin:
    """Fetch event context and relations."""

    async def get_event_context(
        self,
        room_id: str,
        event_id: str,
        limit: int | None = None,
        filter: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Get context around an event

        Args:
            room_id: Room ID
            event_id: Event ID
            limit: Optional limit
            filter: Optional filter

        Returns:
            Context response
        """
        room = quote_path_segment(room_id)
        event = quote_path_segment(event_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/context/{event}"
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if filter is not None:
            params["filter"] = json.dumps(filter, ensure_ascii=False)
        return await self._request("GET", endpoint, params=params)

    async def get_event_relations(
        self,
        room_id: str,
        event_id: str,
        rel_type: str,
        event_type: str | None = None,
        from_token: str | None = None,
        to_token: str | None = None,
        limit: int | None = None,
        recurse: bool | None = None,
    ) -> dict[str, Any]:
        """Get relations for an event.

        ``recurse`` is the Matrix v1.10 / MSC3981 stable query flag. When true,
        the homeserver may include indirect relations in addition to direct
        children. ``None`` omits the flag for compatibility with older servers.
        """
        room = quote_path_segment(room_id)
        event = quote_path_segment(event_id)
        relation = quote_path_segment(rel_type)
        path = f"/_matrix/client/v3/rooms/{room}/relations/{event}/{relation}"
        if event_type:
            path += f"/{quote_path_segment(event_type)}"
        params: dict[str, Any] = {}
        if from_token:
            params["from"] = from_token
        if to_token:
            params["to"] = to_token
        if limit is not None:
            params["limit"] = limit
        if recurse is not None:
            params["recurse"] = "true" if recurse else "false"
        return await self._request("GET", path, params=params)
