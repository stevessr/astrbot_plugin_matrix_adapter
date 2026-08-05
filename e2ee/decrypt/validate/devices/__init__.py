"""Device validation for decrypted message senders."""

from .candidate import E2EEManagerDecryptDeviceCandidateMixin
from .core import E2EEManagerDecryptDeviceOrchestratorMixin
from .local import E2EEManagerDecryptDeviceLocalMixin
from .server import E2EEManagerDecryptDeviceServerMixin


class E2EEManagerDecryptDeviceValidateMixin(
    E2EEManagerDecryptDeviceOrchestratorMixin,
    E2EEManagerDecryptDeviceCandidateMixin,
    E2EEManagerDecryptDeviceLocalMixin,
    E2EEManagerDecryptDeviceServerMixin,
):
    """Resolve sender keys to validated user/device pairs."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    E2EEManagerDecryptDeviceOrchestratorMixin,
    E2EEManagerDecryptDeviceCandidateMixin,
    E2EEManagerDecryptDeviceLocalMixin,
    E2EEManagerDecryptDeviceServerMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerDecryptDeviceValidateMixin, _method_name, _method)


__all__ = ["E2EEManagerDecryptDeviceValidateMixin"]
