"""Room member loading for event dispatch."""

from astrbot.api import logger


class MatrixEventProcessorRoomMembersOrchestratorMixin:
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

        try:
            await self._fetch_and_process_room_members(room_id, room)
            await self._persist_room_members(room_id, room)
        except Exception as e:
            logger.error(f"获取房间 {room_id} 成员列表失败：{e}")
            self._apply_summary_member_count(room_id, room, room_data)

        return False


__all__ = ["MatrixEventProcessorRoomMembersOrchestratorMixin"]
