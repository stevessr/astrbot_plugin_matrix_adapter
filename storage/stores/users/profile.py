"""Interacted-user profile persistence operations."""

from astrbot.api import logger


class MatrixUserProfileMixin:
    """Persist interacted user display names and avatars."""

    def upsert(self, user_id: str, display_name: str | None, avatar_url: str | None):
        if not user_id:
            return
        existing = self.get(user_id) or {"user_id": user_id}
        updated = False

        if display_name and display_name != existing.get("display_name"):
            existing["display_name"] = display_name
            updated = True
        if avatar_url and avatar_url != existing.get("avatar_url"):
            existing["avatar_url"] = avatar_url
            updated = True

        if not updated:
            return

        try:
            self._store.upsert(user_id, existing)
            self._cache[user_id] = existing
            self._cache.move_to_end(user_id, last=True)
            while len(self._cache) > self._MAX_CACHE_ENTRIES:
                self._cache.popitem(last=False)
        except Exception as e:
            logger.debug(f"Failed to save user profile {user_id}: {e}")
