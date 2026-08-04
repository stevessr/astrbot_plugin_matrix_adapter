"""Room name, topic, and avatar state-event operations."""

from typing import Any

from .....constants import M_ROOM_AVATAR, M_ROOM_NAME, M_ROOM_TOPIC


class RoomStateIdentityMixin:
    """Set room name, topic, and avatar."""

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
