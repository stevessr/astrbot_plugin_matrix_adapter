"""Room state persistence to the storage backend."""

import asyncio


class MatrixEventProcessorPersistMixin:
    """Persist room state to the storage backend."""

    async def _persist_room_state(self, room) -> None:
        """将房间状态/成员数据持久化到存储后端。"""
        await asyncio.to_thread(
            self.room_member_store.upsert,
            room_id=room.room_id,
            members=room.members,
            member_avatars=room.member_avatars,
            member_count=room.member_count,
            is_direct=room.is_direct,
            room_name=room.display_name,
            topic=room.topic,
            avatar_url=room.avatar_url,
            join_rules=room.join_rules,
            power_levels=room.power_levels,
            history_visibility=room.history_visibility,
            guest_access=room.guest_access,
            canonical_alias=room.canonical_alias,
            room_aliases=room.room_aliases,
            encryption=room.encryption,
            create=room.create,
            tombstone=room.tombstone,
            pinned_events=room.pinned_events,
            space_children=room.space_children,
            space_parents=room.space_parents,
            third_party_invites=room.third_party_invites,
            state_events=room.state_events,
        )
