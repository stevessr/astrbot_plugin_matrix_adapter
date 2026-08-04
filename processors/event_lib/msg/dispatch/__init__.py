"""Message event processing, split by responsibility.

Public symbols re-exported for backward compatibility.
"""

from .core import MatrixEventProcessorMessagesCoreMixin
from .decrypt import MatrixEventProcessorMessagesDecryptMixin
from .delivery import MatrixEventProcessorMessagesDeliveryMixin
from .edit import MatrixEventProcessorMessagesEditMixin


class MatrixEventProcessorMessagesOperationsMixin(
    MatrixEventProcessorMessagesCoreMixin,
    MatrixEventProcessorMessagesDecryptMixin,
    MatrixEventProcessorMessagesEditMixin,
    MatrixEventProcessorMessagesDeliveryMixin,
):
    """Mixin for message event processing."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixEventProcessorMessagesCoreMixin,
    MatrixEventProcessorMessagesDecryptMixin,
    MatrixEventProcessorMessagesEditMixin,
    MatrixEventProcessorMessagesDeliveryMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixEventProcessorMessagesOperationsMixin, _method_name, _method)


__all__ = [
    "MatrixEventProcessorMessagesOperationsMixin",
    "MatrixEventProcessorMessagesCoreMixin",
    "MatrixEventProcessorMessagesDecryptMixin",
    "MatrixEventProcessorMessagesEditMixin",
    "MatrixEventProcessorMessagesDeliveryMixin",
]
