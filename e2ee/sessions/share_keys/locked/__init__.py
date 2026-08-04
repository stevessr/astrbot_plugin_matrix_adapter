"""Locked room-key device distribution implementation.

Public symbols re-exported for backward compatibility.
"""

from .core import E2EEManagerSessionShareKeysLockedCoreMixin
from .devices import E2EEManagerSessionShareKeysDeviceMixin
from .send import E2EEManagerSessionShareKeysSendMixin


class E2EEManagerSessionShareKeysLockedMixin(
    E2EEManagerSessionShareKeysLockedCoreMixin,
    E2EEManagerSessionShareKeysDeviceMixin,
    E2EEManagerSessionShareKeysSendMixin,
):
    """在会话锁内查询设备、建立 Olm 并发送房间密钥。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    E2EEManagerSessionShareKeysLockedCoreMixin,
    E2EEManagerSessionShareKeysDeviceMixin,
    E2EEManagerSessionShareKeysSendMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerSessionShareKeysLockedMixin, _method_name, _method)


__all__ = [
    "E2EEManagerSessionShareKeysDeviceMixin",
    "E2EEManagerSessionShareKeysLockedCoreMixin",
    "E2EEManagerSessionShareKeysLockedMixin",
    "E2EEManagerSessionShareKeysSendMixin",
]
