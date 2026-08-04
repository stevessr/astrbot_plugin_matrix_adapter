"""Device-list change hooks for room-key sharing.

Public symbols re-exported for backward compatibility.
"""

from .core import E2EEManagerSessionShareEventsDevicesCoreMixin
from .refresh import E2EEManagerSessionShareEventsDevicesRefreshMixin
from .rooms import E2EEManagerSessionShareEventsDevicesRoomsMixin


class E2EEManagerSessionShareEventsDevicesMixin(
    E2EEManagerSessionShareEventsDevicesCoreMixin,
    E2EEManagerSessionShareEventsDevicesRefreshMixin,
    E2EEManagerSessionShareEventsDevicesRoomsMixin,
):
    """处理设备列表增删与房间密钥缓存更新。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    E2EEManagerSessionShareEventsDevicesCoreMixin,
    E2EEManagerSessionShareEventsDevicesRefreshMixin,
    E2EEManagerSessionShareEventsDevicesRoomsMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerSessionShareEventsDevicesMixin, _method_name, _method)


__all__ = [
    "E2EEManagerSessionShareEventsDevicesCoreMixin",
    "E2EEManagerSessionShareEventsDevicesMixin",
    "E2EEManagerSessionShareEventsDevicesRefreshMixin",
    "E2EEManagerSessionShareEventsDevicesRoomsMixin",
]
