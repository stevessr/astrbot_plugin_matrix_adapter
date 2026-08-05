"""Record persistence for upserts."""

from astrbot.api import logger


class MatrixRoomMemberRecordsPersistMixin:
    """Persist a record to the store and maintain the cache."""

    def _persist_record(self, room_id: str, existing: dict, member_count: int) -> None:
        try:
            self._store.upsert(room_id, existing)
            self._cache[room_id] = existing
            self._cache.move_to_end(room_id, last=True)
            while len(self._cache) > self._MAX_CACHE_ENTRIES:
                self._cache.popitem(last=False)
            logger.info(f"已保存房间成员数据：{room_id} ({member_count} 个成员)")
        except Exception as e:
            logger.error(f"保存房间成员数据失败 {room_id}: {e}")
