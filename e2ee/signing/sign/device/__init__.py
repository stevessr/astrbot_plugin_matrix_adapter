"""Device-signing operations for cross-signing."""

from .core import CrossSigningDeviceSignCoreMixin
from .verify import CrossSigningDeviceSignVerifyMixin


class CrossSigningDeviceSignMixin(
    CrossSigningDeviceSignCoreMixin,
    CrossSigningDeviceSignVerifyMixin,
):
    """为设备上传 self-signing 签名。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _mixin in (
    CrossSigningDeviceSignCoreMixin,
    CrossSigningDeviceSignVerifyMixin,
):
    for _name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(CrossSigningDeviceSignMixin, _name, _method)

__all__ = ["CrossSigningDeviceSignMixin"]
