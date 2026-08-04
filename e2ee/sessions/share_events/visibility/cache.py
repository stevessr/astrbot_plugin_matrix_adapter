"""Room member and encryption-config cache helpers."""


class E2EEManagerSessionShareEventsVisibilityCacheMixin:
    """缓存房间加密配置并解析历史可见性策略。"""

    def invalidate_room_members_cache(self, room_id: str) -> None:
        """Invalidate member cache for a room to force fresh state query next time."""
        cache = getattr(self, "_room_members_cache", None)
        if isinstance(cache, dict):
            cache.pop(room_id, None)

    def set_room_encryption_config(self, room_id: str, content: object) -> None:
        """Cache the current m.room.encryption rotation policy for a room."""
        configs = getattr(self, "_room_encryption_config", None)
        if not isinstance(configs, dict):
            configs = {}
            self._room_encryption_config = configs
        if isinstance(room_id, str) and room_id and isinstance(content, dict):
            configs[room_id] = dict(content)
