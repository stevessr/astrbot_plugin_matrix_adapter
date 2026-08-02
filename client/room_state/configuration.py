"""Room invitation and configurable state-event operations."""

from typing import Any

from ...constants import (
    M_ROOM_AVATAR,
    M_ROOM_CANONICAL_ALIAS,
    M_ROOM_GUEST_ACCESS,
    M_ROOM_HISTORY_VISIBILITY,
    M_ROOM_JOIN_RULES,
    M_ROOM_NAME,
    M_ROOM_TOPIC,
)
from ..path_utils import quote_path_segment


class RoomStateConfigurationMixin:
    """Third-party invitations and common room state settings."""

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
            room_id=room_id, event_type=M_ROOM_NAME, content={"name": name}
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
            room_id=room_id, event_type=M_ROOM_TOPIC, content={"topic": topic}
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
            event_type=M_ROOM_AVATAR,
            content={"url": avatar_url},
        )

    async def set_room_join_rules(self, room_id: str, join_rule: str) -> dict[str, Any]:
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
            event_type=M_ROOM_JOIN_RULES,
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
            event_type=M_ROOM_HISTORY_VISIBILITY,
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
            event_type=M_ROOM_GUEST_ACCESS,
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
            event_type=M_ROOM_CANONICAL_ALIAS,
            content=content,
        )
