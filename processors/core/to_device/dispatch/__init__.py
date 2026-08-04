"""To-device event dispatch operations, split by responsibility.

Public symbols re-exported for backward compatibility.
"""

from .core import MatrixEventProcessorToDeviceCoreMixin
from .encrypted import MatrixEventProcessorToDeviceEncryptedMixin
from .keys import MatrixEventProcessorToDeviceKeysMixin


class MatrixEventProcessorToDeviceOperationsMixin(
    MatrixEventProcessorToDeviceCoreMixin,
    MatrixEventProcessorToDeviceEncryptedMixin,
    MatrixEventProcessorToDeviceKeysMixin,
):
    """Handle room-key requests, withheld notices, and encrypted to-device events."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixEventProcessorToDeviceCoreMixin,
    MatrixEventProcessorToDeviceEncryptedMixin,
    MatrixEventProcessorToDeviceKeysMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixEventProcessorToDeviceOperationsMixin, _method_name, _method)


__all__ = [
    "MatrixEventProcessorToDeviceCoreMixin",
    "MatrixEventProcessorToDeviceEncryptedMixin",
    "MatrixEventProcessorToDeviceKeysMixin",
    "MatrixEventProcessorToDeviceOperationsMixin",
]
