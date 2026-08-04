"""Room join membership transition handling."""

import asyncio

from astrbot.api import logger


class MatrixEventProcessorMembershipJoinMixin:
    """Handle room joins and persist profile updates."""

    async def _handle_member_join(
        self, room, user_id, display_name, avatar_url, e2ee_manager
    ):
        is_new_member = user_id not in room.members
        room.members[user_id] = display_name
        if avatar_url:
            room.member_avatars[user_id] = avatar_url
        await asyncio.to_thread(
            self.user_store.upsert, user_id, display_name, avatar_url
        )
        if is_new_member:
            room.member_count += 1
            logger.info(
                f"用户 {user_id} ({display_name}) 加入房间 {room.room_id}，"
                f"当前人数：{room.member_count}"
            )
            # Update room member storage
            await self._persist_room_member_state(room)
            if e2ee_manager:
                try:
                    e2ee_manager.invalidate_room_members_cache(room.room_id)
                    if user_id != self.user_id:
                        await e2ee_manager.on_room_member_joined(room.room_id, user_id)
                except Exception as e:
                    logger.debug(f"成员加入后的主动密钥分发失败：{e}")
