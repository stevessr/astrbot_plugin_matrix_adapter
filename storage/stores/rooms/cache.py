"""Room member cache and deletion operations."""

from typing import Any

from astrbot.api import logger


class MatrixRoomCacheMixin:
    """Read and evict room member records through the local cache."""

    def get(self, room_id: str) -> dict[str, Any] | None:
        """Get room member data from storage."""
        if not room_id:
            return None
        if room_id in self._cache:
            self._cache.move_to_end(room_id, last=True)
            return self._cache[room_id]
        try:
            data = self._store.get(room_id)
            if isinstance(data, dict):
                self._cache[room_id] = data
                self._cache.move_to_end(room_id, last=True)
                while len(self._cache) > self._MAX_CACHE_ENTRIES:
                    self._cache.popitem(last=False)
                return data
        except Exception as e:
            logger.debug(f"Failed to read room member data {room_id}: {e}")
        return None

    def delete(self, room_id: str):
        """Delete room member data from storage."""
        if not room_id:
            return
        try:
            self._store.delete(room_id)
            if room_id in self._cache:
                del self._cache[room_id]
            logger.debug(f"Deleted room member data: {room_id}")
        except Exception as e:
            logger.debug(f"Failed to delete room member data {room_id}: {e}")
