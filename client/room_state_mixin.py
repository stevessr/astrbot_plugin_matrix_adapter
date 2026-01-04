"""
Matrix HTTP Client - Room State Mixin
Provides room state helper methods
"""

from typing import Any


class RoomStateMixin:
    """Room state helper methods for Matrix client"""

    async def get_joined_members(self, room_id: str) -> dict[str, Any]:
        """
        Get joined members in a room

        Args:
            room_id: Room ID

        Returns:
            Joined members response
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/joined_members"
        return await self._request("GET", endpoint)

    async def get_room_state_ids(self, room_id: str) -> dict[str, Any]:
        """
        Get state event IDs for a room

        Args:
            room_id: Room ID

        Returns:
            State IDs response
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/state_ids"
        return await self._request("GET", endpoint)

    async def get_room_summary(self, room_id: str) -> dict[str, Any]:
        """
        Get room summary

        Args:
            room_id: Room ID

        Returns:
            Summary response
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/summary"
        return await self._request("GET", endpoint)

    async def timestamp_to_event(
        self, room_id: str, timestamp: int, direction: str = "b"
    ) -> dict[str, Any]:
        """
        Find the event at or near a timestamp

        Args:
            room_id: Room ID
            timestamp: Timestamp in milliseconds
            direction: "b" or "f"

        Returns:
            Event lookup response
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/timestamp_to_event"
        params = {"ts": timestamp, "dir": direction}
        return await self._request("GET", endpoint, params=params)

    async def initial_sync(
        self, room_id: str, limit: int | None = None, archived: bool | None = None
    ) -> dict[str, Any]:
        """
        Get room initial sync (deprecated but supported by some servers)

        Args:
            room_id: Room ID
            limit: Optional limit
            archived: Include archived rooms if True

        Returns:
            Initial sync response
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/initialSync"
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if archived is not None:
            params["archived"] = "true" if archived else "false"
        return await self._request("GET", endpoint, params=params)

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
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/invite"
        data = {"id_server": id_server, "medium": medium, "address": address}
        return await self._request("POST", endpoint, data=data)

    async def set_room_name(self, room_id: str, name: str) -> dict[str, Any]:
        """
        Set room name

        Args:
            room_id: Room ID
            name: Room name

        Returns:
            Response with event_id
        """
        return await self.set_room_state_event(
            room_id=room_id, event_type="m.room.name", content={"name": name}
        )

    async def set_room_topic(self, room_id: str, topic: str) -> dict[str, Any]:
        """
        Set room topic

        Args:
            room_id: Room ID
            topic: Room topic

        Returns:
            Response with event_id
        """
        return await self.set_room_state_event(
            room_id=room_id, event_type="m.room.topic", content={"topic": topic}
        )

    async def set_room_avatar(self, room_id: str, avatar_url: str) -> dict[str, Any]:
        """
        Set room avatar URL

        Args:
            room_id: Room ID
            avatar_url: MXC URL

        Returns:
            Response with event_id
        """
        return await self.set_room_state_event(
            room_id=room_id,
            event_type="m.room.avatar",
            content={"url": avatar_url},
        )

    async def set_room_join_rules(
        self, room_id: str, join_rule: str
    ) -> dict[str, Any]:
        """
        Set room join rules

        Args:
            room_id: Room ID
            join_rule: "public", "invite", "knock", "restricted"

        Returns:
            Response with event_id
        """
        return await self.set_room_state_event(
            room_id=room_id,
            event_type="m.room.join_rules",
            content={"join_rule": join_rule},
        )

    async def set_room_history_visibility(
        self, room_id: str, history_visibility: str
    ) -> dict[str, Any]:
        """
        Set room history visibility

        Args:
            room_id: Room ID
            history_visibility: "invited", "joined", "shared", "world_readable"

        Returns:
            Response with event_id
        """
        return await self.set_room_state_event(
            room_id=room_id,
            event_type="m.room.history_visibility",
            content={"history_visibility": history_visibility},
        )

    async def set_room_guest_access(
        self, room_id: str, guest_access: str
    ) -> dict[str, Any]:
        """
        Set room guest access

        Args:
            room_id: Room ID
            guest_access: "can_join" or "forbidden"

        Returns:
            Response with event_id
        """
        return await self.set_room_state_event(
            room_id=room_id,
            event_type="m.room.guest_access",
            content={"guest_access": guest_access},
        )

    async def set_room_canonical_alias(
        self, room_id: str, alias: str | None, alt_aliases: list[str] | None = None
    ) -> dict[str, Any]:
        """
        Set room canonical alias

        Args:
            room_id: Room ID
            alias: Canonical alias or None to clear
            alt_aliases: Optional alternative aliases

        Returns:
            Response with event_id
        """
        content: dict[str, Any] = {}
        if alias:
            content["alias"] = alias
        if alt_aliases:
            content["alt_aliases"] = alt_aliases
        return await self.set_room_state_event(
            room_id=room_id,
            event_type="m.room.canonical_alias",
            content=content,
        )
