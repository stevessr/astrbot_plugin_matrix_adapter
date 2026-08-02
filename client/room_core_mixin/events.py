"""Room event retrieval and search operations."""

from typing import Any

from ..path_utils import quote_path_segment


class RoomEventSearchMixin:
    """Fetch individual room events and search the Matrix event index."""

    async def get_event(self, room_id: str, event_id: str) -> dict[str, Any]:
        """
        Get a single event from a room

        Args:
            room_id: Room ID
            event_id: Event ID to fetch

        Returns:
            Event data
        """
        room = quote_path_segment(room_id)
        event = quote_path_segment(event_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/event/{event}"
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


__all__ = ["RoomEventSearchMixin"]
