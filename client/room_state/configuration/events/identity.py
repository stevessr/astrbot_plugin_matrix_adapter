"""Room name, topic, and avatar state-event operations."""

from typing import Any

from .....constants import M_ROOM_AVATAR, M_ROOM_NAME, M_ROOM_TOPIC
from .....room_topic import build_room_topic_content


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

    async def set_room_topic(
        self,
        room_id: str,
        topic: str,
        formatted_topic: str | None = None,
    ) -> dict[str, Any]:
        """Set a Matrix v1.15 rich room topic.

        ``topic`` is always emitted as the backwards-compatible plain fallback.
        When ``formatted_topic`` is provided it is emitted as the HTML variant
        inside the stable ``m.topic``/``m.text`` content block.
        """
        return await self.set_room_state_event(
            room_id=room_id,
            event_type=M_ROOM_TOPIC,
            content=build_room_topic_content(
                topic,
                formatted_topic=formatted_topic,
            ),
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
