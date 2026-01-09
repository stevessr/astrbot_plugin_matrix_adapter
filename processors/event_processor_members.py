"""
Matrix Event Processor - member/profile handlers.
"""

from astrbot.api import logger

from ..room_member_store import MatrixRoomMemberStore
from ..user_store import MatrixUserStore


class MatrixEventProcessorMembers:
    """Mixin for membership updates and profile persistence."""

    def _init_member_storage(self):
        self.user_store = MatrixUserStore()
        self.room_member_store = MatrixRoomMemberStore()

    async def load_room_members_from_storage(self, room):
        """
        Load room member data from persistent storage.

        Args:
            room: Room object to populate with member data

        Returns:
            True if data was loaded from storage, False otherwise
        """
        room_data = self.room_member_store.get(room.room_id)
        if not room_data:
            return False

        room.members = room_data.get("members", {})
        room.member_avatars = room_data.get("member_avatars", {})
        room.member_count = room_data.get("member_count", 0)
        if "is_direct" in room_data:
            room.is_direct = room_data.get("is_direct")

        logger.debug(
            f"从存储加载房间 {room.room_id} 成员数据：{room.member_count} 个成员"
        )
        return True

    async def _persist_interacted_user(self, room, event):
        """Persist profile info for interacted users."""
        user_id = getattr(event, "sender", None)
        if not user_id:
            return
        display_name = room.members.get(user_id, user_id)
        avatar_url = room.member_avatars.get(user_id)
        if not avatar_url and self.client:
            try:
                avatar_url = await self.client.get_avatar_url(user_id)
            except Exception:
                avatar_url = None
        self.user_store.upsert(user_id, display_name, avatar_url)

    async def _handle_member_event(self, room, event_data: dict):
        """Handle m.room.member changes and persist profile updates."""
        user_id = event_data.get("state_key")
        if not user_id:
            return
        content = event_data.get("content", {})
        membership = content.get("membership")
        display_name = content.get("displayname") or room.members.get(user_id, user_id)
        avatar_url = content.get("avatar_url") or room.member_avatars.get(user_id)

        if membership == "join":
            is_new_member = user_id not in room.members
            room.members[user_id] = display_name
            if avatar_url:
                room.member_avatars[user_id] = avatar_url
            self.user_store.upsert(user_id, display_name, avatar_url)
            if is_new_member:
                room.member_count += 1
                logger.info(
                    f"用户 {user_id} ({display_name}) 加入房间 {room.room_id}，"
                    f"当前人数：{room.member_count}"
                )
                # Update room member storage
                self.room_member_store.upsert(
                    room_id=room.room_id,
                    members=room.members,
                    member_avatars=room.member_avatars,
                    member_count=room.member_count,
                    is_direct=room.is_direct,
                )
        elif membership in ("leave", "ban"):
            was_member = user_id in room.members
            room.members.pop(user_id, None)
            room.member_avatars.pop(user_id, None)
            if was_member and room.member_count > 0:
                room.member_count -= 1
                logger.info(
                    f"用户 {user_id} ({display_name}) 离开房间 {room.room_id}，"
                    f"当前人数：{room.member_count}"
                )
                # Update room member storage
                self.room_member_store.upsert(
                    room_id=room.room_id,
                    members=room.members,
                    member_avatars=room.member_avatars,
                    member_count=room.member_count,
                    is_direct=room.is_direct,
                )
        else:
            # Membership changes without join/leave still update profile fields if present.
            if content.get("displayname") or content.get("avatar_url"):
                room.members[user_id] = display_name
                if avatar_url:
                    room.member_avatars[user_id] = avatar_url
                self.user_store.upsert(user_id, display_name, avatar_url)
                # Update room member storage
                self.room_member_store.upsert(
                    room_id=room.room_id,
                    members=room.members,
                    member_avatars=room.member_avatars,
                    member_count=room.member_count,
                    is_direct=room.is_direct,
                )
