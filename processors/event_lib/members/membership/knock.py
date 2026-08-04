"""Room knock membership transition handling."""

import asyncio

from astrbot.api import logger


class MatrixEventProcessorMembershipKnockMixin:
    """Handle room knock requests (MSC2403)."""

    async def _handle_member_knock(self, room, user_id, display_name, avatar_url):
        # MSC2403: a user is requesting to join the room.
        # Update profile info and persist; the knock system message
        # is rendered by the receiver's room_state handler.
        if display_name or avatar_url:
            room.members[user_id] = display_name
            if avatar_url:
                room.member_avatars[user_id] = avatar_url
            user_store = getattr(self, "user_store", None)
            if user_store is not None:
                await asyncio.to_thread(
                    user_store.upsert, user_id, display_name, avatar_url
                )
        logger.info(f"用户 {user_id} ({display_name}) 敲门房间 {room.room_id}")
