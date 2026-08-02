"""Device-cache key helpers for room-key sharing."""


class E2EEManagerSessionShareKeysCacheMixin:
    """构造设备密钥共享缓存键。"""

    @staticmethod
    def _device_cache_key(user_id: str, device_id: str, curve25519_key: str) -> str:
        return f"{user_id}|{device_id}|{curve25519_key}"
