"""Room member loading for event dispatch."""

import asyncio

from astrbot.api import logger

from .....constants import M_ROOM_MEMBER, MEMBERSHIP_JOIN


class MatrixEventProcessorRoomMembersMixin:
    """Load and persist room members for dispatch."""

    async def _load_room_members(
        self,
        room_id: str,
        room,
        room_data: dict,
    ) -> bool:
        """Populate room members, returning whether storage was used."""
        # Try to load from storage first to avoid unnecessary API calls
        loaded_from_storage = await self.load_room_members_from_storage(room)

        if loaded_from_storage:
            return True

        # Fetch complete member list from API to ensure accuracy
        try:
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

            # Persist room member data to storage
            await asyncio.to_thread(
                self.room_member_store.upsert,
                room_id=room.room_id,
                members=room.members,
                member_avatars=room.member_avatars,
                member_count=room.member_count,
                is_direct=room.is_direct,
            )

            # Persist individual user profiles to storage
            for user_id, display_name in room.members.items():
                avatar_url = room.member_avatars.get(user_id)
                await asyncio.to_thread(
                    self.user_store.upsert,
                    user_id,
                    display_name,
                    avatar_url,
                )

        except Exception as e:
            logger.error(f"获取房间 {room_id} 成员列表失败：{e}")
            # Final fallback: use /sync summary counts
            summary = room_data.get("summary", {})
            joined_count = summary.get("joined_member_count")
            invited_count = summary.get("invited_member_count")
            if isinstance(joined_count, int):
                room.member_count = joined_count + (
                    invited_count if isinstance(invited_count, int) else 0
                )
                logger.warning(
                    f"房间 {room_id} 使用备用方案（summary）: "
                    f"joined={joined_count}, invited={invited_count}, "
                    f"total={room.member_count}"
                )

        return False
