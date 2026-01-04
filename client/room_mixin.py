"""
Matrix HTTP Client - Room Mixin
Provides room-related API methods
"""

from typing import Any


class RoomMixin:
    """Room-related methods for Matrix client"""

    async def join_room(self, room_id: str) -> dict[str, Any]:
        """
        Join a room

        Args:
            room_id: Room ID or alias

        Returns:
            Join response with room_id
        """
        endpoint = f"/_matrix/client/v3/join/{room_id}"
        return await self._request("POST", endpoint, data={})

    async def leave_room(self, room_id: str) -> dict[str, Any]:
        """
        Leave a room

        Args:
            room_id: Room ID

        Returns:
            Leave response
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/leave"
        return await self._request("POST", endpoint, data={})

    async def get_room_members(self, room_id: str) -> dict[str, Any]:
        """
        Get room members

        Args:
            room_id: Room ID

        Returns:
            Room members data
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/members"
        return await self._request("GET", endpoint)

    async def room_messages(
        self,
        room_id: str,
        from_token: str | None = None,
        to_token: str | None = None,
        direction: str = "b",
        limit: int = 10,
    ) -> dict[str, Any]:
        """
        Get messages from a room

        Args:
            room_id: Room ID
            from_token: Token to start from
            to_token: Token to end at
            direction: Direction to paginate ('b' for backwards, 'f' for forwards)
            limit: Maximum number of events to return

        Returns:
            Response with chunk of events and pagination tokens
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/messages"
        params = {
            "dir": direction,
            "limit": limit,
        }
        if from_token:
            params["from"] = from_token
        if to_token:
            params["to"] = to_token

        return await self._request("GET", endpoint, params=params)

    async def get_joined_rooms(self) -> list[str]:
        """
        Get list of joined room IDs

        Returns:
            List of room IDs
        """
        response = await self._request("GET", "/_matrix/client/v3/joined_rooms")
        return response.get("joined_rooms", [])

    async def get_room_state(self, room_id: str) -> list[dict[str, Any]]:
        """
        Get full state for a room

        Args:
            room_id: Room ID

        Returns:
            List of state events
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/state"
        return await self._request("GET", endpoint)

    async def is_room_encrypted(self, room_id: str) -> bool:
        """
        Check if a room has encryption enabled

        Args:
            room_id: Room ID

        Returns:
            True if room is encrypted
        """
        try:
            state = await self.get_room_state(room_id)
            for event in state:
                if event.get("type") == "m.room.encryption":
                    return True
            return False
        except Exception:
            return False

    async def get_room_state_event(
        self, room_id: str, event_type: str, state_key: str = ""
    ) -> dict[str, Any]:
        """
        Get a specific state event from a room

        Args:
            room_id: Room ID
            event_type: Event type (e.g., im.vector.modular.widgets)
            state_key: State key (widget ID for widgets)

        Returns:
            State event content
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/state/{event_type}/{state_key}"
        return await self._request("GET", endpoint)

    async def set_room_state_event(
        self,
        room_id: str,
        event_type: str,
        content: dict[str, Any],
        state_key: str = "",
    ) -> dict[str, Any]:
        """
        Set a state event in a room

        Args:
            room_id: Room ID
            event_type: Event type (e.g., im.vector.modular.widgets)
            content: Event content
            state_key: State key (widget ID for widgets)

        Returns:
            Response with event_id
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/state/{event_type}/{state_key}"
        return await self._request("PUT", endpoint, data=content)

    async def get_event(self, room_id: str, event_id: str) -> dict[str, Any]:
        """
        Get a single event from a room

        Args:
            room_id: Room ID
            event_id: Event ID to fetch

        Returns:
            Event data
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/event/{event_id}"
        return await self._request("GET", endpoint)

    async def search(
        self,
        search_term: str,
        keys: list[str] | None = None,
        filter: dict[str, Any] | None = None,
        order_by: str = "recent",
        event_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Search for events matching a search term

        Args:
            search_term: The term to search for
            keys: List of keys to search (default: ["content.body"])
            filter: Filter to apply to the search
            order_by: Order by "recent" or "rank" (default: "recent")
            event_context: Event context to include with results

        Returns:
            Search results
        """
        endpoint = "/_matrix/client/v3/search"
        data = {
            "search_categories": {
                "room_events": {
                    "search_term": search_term,
                    "keys": keys or ["content.body"],
                    "filter": filter or {},
                    "order_by": order_by,
                    "event_context": event_context or {},
                }
            }
        }
        return await self._request("POST", endpoint, data=data)

    # ========== Room Directory / Aliases / Public Rooms ==========

    async def create_room_alias(self, room_alias: str, room_id: str) -> dict[str, Any]:
        """
        Create or update a room alias

        Args:
            room_alias: Room alias (e.g., #alias:example.com)
            room_id: Room ID

        Returns:
            Empty dict on success
        """
        endpoint = f"/_matrix/client/v3/directory/room/{room_alias}"
        return await self._request("PUT", endpoint, data={"room_id": room_id})

    async def delete_room_alias(self, room_alias: str) -> dict[str, Any]:
        """
        Delete a room alias

        Args:
            room_alias: Room alias (e.g., #alias:example.com)

        Returns:
            Empty dict on success
        """
        endpoint = f"/_matrix/client/v3/directory/room/{room_alias}"
        return await self._request("DELETE", endpoint)

    async def get_room_alias(self, room_alias: str) -> dict[str, Any]:
        """
        Resolve a room alias

        Args:
            room_alias: Room alias (e.g., #alias:example.com)

        Returns:
            Dict containing room_id and servers
        """
        endpoint = f"/_matrix/client/v3/directory/room/{room_alias}"
        return await self._request("GET", endpoint)

    async def list_public_rooms(
        self,
        server: str | None = None,
        limit: int | None = None,
        since: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        List public rooms

        Args:
            server: Optional server to query
            limit: Optional limit
            since: Pagination token
            filter: Optional filter (uses POST when provided)

        Returns:
            Public rooms response
        """
        endpoint = "/_matrix/client/v3/publicRooms"
        params: dict[str, Any] = {}
        if server:
            params["server"] = server
        if limit is not None:
            params["limit"] = limit
        if since:
            params["since"] = since

        if filter is None:
            return await self._request("GET", endpoint, params=params)

        data: dict[str, Any] = {"filter": filter}
        if server:
            data["server"] = server
        if limit is not None:
            data["limit"] = limit
        if since:
            data["since"] = since
        return await self._request("POST", endpoint, data=data)

    # ========== Room Management ==========

    async def forget_room(self, room_id: str) -> dict[str, Any]:
        """
        Forget a room (after leaving)

        Args:
            room_id: Room ID

        Returns:
            Empty dict on success
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/forget"
        return await self._request("POST", endpoint, data={})

    async def upgrade_room(self, room_id: str, new_version: str) -> dict[str, Any]:
        """
        Upgrade a room to a new version

        Args:
            room_id: Room ID
            new_version: New room version (e.g., "10")

        Returns:
            Response with replacement_room
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/upgrade"
        return await self._request("POST", endpoint, data={"new_version": new_version})

    async def knock_room(
        self, room_id_or_alias: str, reason: str | None = None
    ) -> dict[str, Any]:
        """
        Knock on a room (if supported by server)

        Args:
            room_id_or_alias: Room ID or alias
            reason: Optional reason

        Returns:
            Knock response with room_id
        """
        endpoint = f"/_matrix/client/v3/knock/{room_id_or_alias}"
        data: dict[str, Any] = {}
        if reason:
            data["reason"] = reason
        return await self._request("POST", endpoint, data=data)

    async def get_room_hierarchy(
        self, room_id: str, limit: int | None = None, from_token: str | None = None
    ) -> dict[str, Any]:
        """
        Get room hierarchy (spaces)

        Args:
            room_id: Room ID
            limit: Optional limit
            from_token: Pagination token

        Returns:
            Hierarchy response
        """
        endpoint = f"/_matrix/client/v1/rooms/{room_id}/hierarchy"
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if from_token:
            params["from"] = from_token
        return await self._request("GET", endpoint, params=params)
