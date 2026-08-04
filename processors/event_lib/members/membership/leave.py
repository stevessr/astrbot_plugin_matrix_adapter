"""Room leave/ban membership transition handling."""

from astrbot.api import logger


class MatrixEventProcessorMembershipLeaveMixin:
    """Handle room leaves and bans, rotating E2EE sessions when needed."""

    async def _handle_member_leave(
        self, room, user_id, display_name, e2ee_manager, rotated_for_limited_gap
    ):
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
            await self._persist_room_member_state(room)
        if e2ee_manager and not rotated_for_limited_gap:
            try:
                e2ee_manager.invalidate_room_members_cache(room.room_id)
                if user_id != self.user_id:
                    on_member_left = getattr(
                        e2ee_manager,
                        "on_room_member_left",
                        None,
                    )
                    if callable(on_member_left):
                        await on_member_left(room.room_id, user_id)
            except Exception as e:
                logger.debug(f"成员离开后轮换加密会话失败：{e}")
