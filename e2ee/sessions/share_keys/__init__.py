"""Composable room-key sharing helpers for E2EE sessions."""

from .cache import E2EEManagerSessionShareKeysCacheMixin
from .locked import E2EEManagerSessionShareKeysLockedMixin
from .share import E2EEManagerSessionShareKeysEntryMixin


class E2EEManagerSessionShareKeysMixin(
    E2EEManagerSessionShareKeysCacheMixin,
    E2EEManagerSessionShareKeysEntryMixin,
    E2EEManagerSessionShareKeysLockedMixin,
):
    """分层实现房间密钥缓存、锁和设备分发。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
E2EEManagerSessionShareKeysMixin._device_cache_key = staticmethod(
    E2EEManagerSessionShareKeysCacheMixin._device_cache_key
)

for _method_name in (
    "_share_existing_room_key",
    "ensure_room_keys_sent",
):
    setattr(
        E2EEManagerSessionShareKeysMixin,
        _method_name,
        getattr(E2EEManagerSessionShareKeysEntryMixin, _method_name),
    )

E2EEManagerSessionShareKeysMixin._ensure_room_keys_sent_locked = (
    E2EEManagerSessionShareKeysLockedMixin._ensure_room_keys_sent_locked
)


__all__ = [
    "E2EEManagerSessionShareKeysCacheMixin",
    "E2EEManagerSessionShareKeysEntryMixin",
    "E2EEManagerSessionShareKeysLockedMixin",
    "E2EEManagerSessionShareKeysMixin",
]
