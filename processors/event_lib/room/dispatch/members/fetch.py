"""Room member fetching for event dispatch."""

from astrbot.api import logger

from ......constants import M_ROOM_MEMBER, MEMBERSHIP_JOIN


class MatrixEventProcessorRoomMembersFetchMixin:
    """Fetch and process the complete room member list from the API."""

    async def _fetch_and_process_room_members(self, room_id: str, room) -> None:
        """Fetch the member list from the API and populate the room."""
        # Fetch complete member list from API to ensure accuracy
        members_response = await self.client.get_room_members(room_id)
        chunk = members_response.get("chunk", [])

        # Process member events from API response
        for event in chunk:
            if event.get("type") == M_ROOM_MEMBER:
                user_id = event.get("state_key")
                content = event.get("content", {})
                membership = content.get("membership")

                # Check for is_direct flag in member events
                if (
                    user_id == self.user_id
                    and room.is_direct is None
                    and "is_direct" in content
                ):
                    room.is_direct = self._parse_bool_like(
                        content.get("is_direct"),
                        False,
                    )

                # Only count joined members
                if membership == MEMBERSHIP_JOIN:
                    display_name = content.get("displayname", user_id)
                    room.members[user_id] = display_name
                    avatar_url = content.get("avatar_url")
                    if avatar_url:
                        room.member_avatars[user_id] = avatar_url

        # Set member count from complete member list
        room.member_count = len(room.members)
        logger.info(
            f"房间 {room_id} 成员列表（从 API）: "
            f"总人数={room.member_count}, "
            f"成员列表={list(room.members.keys())}"
        )


__all__ = ["MatrixEventProcessorRoomMembersFetchMixin"]
