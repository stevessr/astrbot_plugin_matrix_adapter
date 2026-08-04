"""Room access and visibility state-event operations."""

from typing import Any

from .....constants import (
    M_ROOM_GUEST_ACCESS,
    M_ROOM_HISTORY_VISIBILITY,
    M_ROOM_JOIN_RULES,
)


class RoomStateAccessMixin:
    """Set room join rules, history visibility, and guest access."""

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
