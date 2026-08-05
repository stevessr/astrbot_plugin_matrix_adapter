"""To-device room-key request and withheld event handling."""

from .request import MatrixEventProcessorToDeviceKeysRequestMixin
from .withheld import MatrixEventProcessorToDeviceKeysWithheldMixin


class MatrixEventProcessorToDeviceKeysMixin(
    MatrixEventProcessorToDeviceKeysRequestMixin,
    MatrixEventProcessorToDeviceKeysWithheldMixin,
):
    """Handle room-key requests and withheld notices."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixEventProcessorToDeviceKeysRequestMixin,
    MatrixEventProcessorToDeviceKeysWithheldMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixEventProcessorToDeviceKeysMixin, _method_name, _method)


__all__ = ["MatrixEventProcessorToDeviceKeysMixin"]
