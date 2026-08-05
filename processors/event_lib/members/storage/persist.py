"""Room member profile persistence handlers."""

import asyncio

from .....storage.stores.rooms import MatrixRoomMemberStore
from .....storage.stores.users import MatrixUserStore


class MatrixEventProcessorMemberStoragePersistMixin:
    """Initialize member stores and persist interacted user profiles."""

    def _init_member_storage(self):
        self.user_store = MatrixUserStore()
        self.room_member_store = MatrixRoomMemberStore()

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
        await asyncio.to_thread(
            self.user_store.upsert, user_id, display_name, avatar_url
        )


__all__ = ["MatrixEventProcessorMemberStoragePersistMixin"]
