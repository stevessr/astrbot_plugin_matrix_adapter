"""Room canonical alias state-event operations."""

from typing import Any

from .....constants import M_ROOM_CANONICAL_ALIAS


class RoomStateAliasesMixin:
    """Set the room canonical alias."""

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
