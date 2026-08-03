"""Interacted-user profile cache operations."""

from typing import Any

from astrbot.api import logger


class MatrixUserCacheMixin:
    """Read user profiles through the local cache."""

    def get(self, user_id: str) -> dict[str, Any] | None:
        if not user_id:
            return None
        if user_id in self._cache:
            self._cache.move_to_end(user_id, last=True)
            return self._cache[user_id]
        try:
            data = self._store.get(user_id)
            if isinstance(data, dict):
                self._cache[user_id] = data
                self._cache.move_to_end(user_id, last=True)
                while len(self._cache) > self._MAX_CACHE_ENTRIES:
                    self._cache.popitem(last=False)
                return data
        except Exception as e:
            logger.debug(f"Failed to read user profile {user_id}: {e}")
        return None
