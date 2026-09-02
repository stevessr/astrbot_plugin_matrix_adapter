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
        """Set the room join rule.

        Stable values used by supported room versions include ``public``,
        ``invite``, ``knock``, ``restricted`` and v1.3 ``knock_restricted``.
        The value is not artificially enum-locked so newer room versions can be
        used without waiting for an adapter release.
        """
        return await self.set_room_state_event(
            room_id=room_id,
            event_type=M_ROOM_JOIN_RULES,
            content={"join_rule": join_rule},
        )

    async def set_room_history_visibility(
        self, room_id: str, history_visibility: str
    ) -> dict[str, Any]:
        """Set room history visibility."""
        return await self.set_room_state_event(
            room_id=room_id,
            event_type=M_ROOM_HISTORY_VISIBILITY,
            content={"history_visibility": history_visibility},
        )

    async def set_room_guest_access(
        self, room_id: str, guest_access: str
    ) -> dict[str, Any]:
        """Set room guest access."""
        return await self.set_room_state_event(
            room_id=room_id,
            event_type=M_ROOM_GUEST_ACCESS,
            content={"guest_access": guest_access},
        )
