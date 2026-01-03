"""
Matrix HTTP Client - Room Mixin
Provides room-related API methods
"""

from typing import Any

from astrbot.api import logger


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
