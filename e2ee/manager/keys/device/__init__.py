"""Device-key upload and verification operations.

Public symbols re-exported for backward compatibility.
"""

from .core import E2EEManagerDeviceKeysCoreMixin
from .generate import E2EEManagerDeviceGenerateMixin
from .identity import E2EEManagerDeviceIdentityMixin
from .verify import E2EEManagerDeviceVerifyMixin


class E2EEManagerDeviceKeysMixin(
    E2EEManagerDeviceKeysCoreMixin,
    E2EEManagerDeviceIdentityMixin,
    E2EEManagerDeviceGenerateMixin,
    E2EEManagerDeviceVerifyMixin,
):
    """上传设备身份密钥、一次性密钥和 fallback key。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    E2EEManagerDeviceKeysCoreMixin,
    E2EEManagerDeviceIdentityMixin,
    E2EEManagerDeviceGenerateMixin,
    E2EEManagerDeviceVerifyMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerDeviceKeysMixin, _method_name, _method)


__all__ = [
    "E2EEManagerDeviceGenerateMixin",
    "E2EEManagerDeviceIdentityMixin",
    "E2EEManagerDeviceKeysCoreMixin",
    "E2EEManagerDeviceKeysMixin",
    "E2EEManagerDeviceVerifyMixin",
]
