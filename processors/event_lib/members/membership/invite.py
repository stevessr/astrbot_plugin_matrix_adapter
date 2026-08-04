"""Room invite membership transition handling."""

import asyncio

from astrbot.api import logger


class MatrixEventProcessorMembershipInviteMixin:
    """Handle room invites and notify the E2EE layer."""

    async def _handle_member_invite(
        self, room, user_id, display_name, avatar_url, e2ee_manager
    ):
        if display_name or avatar_url:
            user_store = getattr(self, "user_store", None)
            if user_store is not None:
                await asyncio.to_thread(
                    user_store.upsert,
                    user_id,
                    display_name,
                    avatar_url,
                )
        if e2ee_manager and user_id != self.user_id:
            try:
                on_member_invited = getattr(
                    e2ee_manager,
                    "on_room_member_invited",
                    None,
                )
                if callable(on_member_invited):
                    await on_member_invited(room.room_id, user_id)
            except Exception as e:
                logger.debug(f"Post-invite room-key sharing failed: {e}")
