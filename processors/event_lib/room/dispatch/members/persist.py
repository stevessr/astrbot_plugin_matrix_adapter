"""Room member persistence for event dispatch."""

import asyncio


class MatrixEventProcessorRoomMembersPersistMixin:
    """Persist room members and user profiles."""

    async def _persist_room_members(self, room_id: str, room) -> None:
        """Persist room member data and interacted user profiles."""
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


__all__ = ["MatrixEventProcessorRoomMembersPersistMixin"]
