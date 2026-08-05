"""Master-key device-signing operations for cross-signing."""

from .core import CrossSigningMasterSignOrchestratorMixin
from .payload import CrossSigningMasterSignPayloadMixin
from .verify import CrossSigningMasterSignVerifyMixin


class CrossSigningMasterSignCoreMixin(
    CrossSigningMasterSignOrchestratorMixin,
    CrossSigningMasterSignPayloadMixin,
    CrossSigningMasterSignVerifyMixin,
):
    """为当前账号 master key 上传当前设备签名。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    CrossSigningMasterSignOrchestratorMixin,
    CrossSigningMasterSignPayloadMixin,
    CrossSigningMasterSignVerifyMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(CrossSigningMasterSignCoreMixin, _method_name, _method)


__all__ = [
    "CrossSigningMasterSignCoreMixin",
    "CrossSigningMasterSignOrchestratorMixin",
    "CrossSigningMasterSignPayloadMixin",
    "CrossSigningMasterSignVerifyMixin",
]
