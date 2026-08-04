"""Validate and process encrypted secret responses from other devices.

Public symbols re-exported for backward compatibility.
"""

from .core import E2EEManagerSecretsReceiveCoreMixin
from .store import E2EEManagerSecretsReceiveStoreMixin


class E2EEManagerSecretsReceiveMixin(
    E2EEManagerSecretsReceiveCoreMixin,
    E2EEManagerSecretsReceiveStoreMixin,
):
    """接收并处理设备间共享秘密。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    E2EEManagerSecretsReceiveCoreMixin,
    E2EEManagerSecretsReceiveStoreMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerSecretsReceiveMixin, _method_name, _method)


__all__ = [
    "E2EEManagerSecretsReceiveCoreMixin",
    "E2EEManagerSecretsReceiveMixin",
    "E2EEManagerSecretsReceiveStoreMixin",
]
