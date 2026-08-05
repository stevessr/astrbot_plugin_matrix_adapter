"""Device-signing operations for cross-signing."""

from .core import CrossSigningDeviceSignOrchestratorMixin
from .fetch import CrossSigningDeviceSignFetchMixin
from .guard import CrossSigningDeviceSignGuardMixin
from .payload import CrossSigningDeviceSignPayloadMixin


class CrossSigningDeviceSignCoreMixin(
    CrossSigningDeviceSignOrchestratorMixin,
    CrossSigningDeviceSignFetchMixin,
    CrossSigningDeviceSignGuardMixin,
    CrossSigningDeviceSignPayloadMixin,
):
    """为设备上传 self-signing 签名。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    CrossSigningDeviceSignOrchestratorMixin,
    CrossSigningDeviceSignFetchMixin,
    CrossSigningDeviceSignGuardMixin,
    CrossSigningDeviceSignPayloadMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(CrossSigningDeviceSignCoreMixin, _method_name, _method)


__all__ = ["CrossSigningDeviceSignCoreMixin"]
