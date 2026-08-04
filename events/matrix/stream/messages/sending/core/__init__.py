"""Live Matrix message sending orchestration.

Public symbols re-exported for backward compatibility.
"""

from .aggregate import MatrixPlatformEventMessagesAggregateMixin
from .core import MatrixPlatformEventMessagesSendStreamCoreMixin
from .live import MatrixPlatformEventMessagesLiveMixin


class MatrixPlatformEventMessagesSendingCoreMixin(
    MatrixPlatformEventMessagesSendStreamCoreMixin,
    MatrixPlatformEventMessagesAggregateMixin,
    MatrixPlatformEventMessagesLiveMixin,
):
    """Send live Matrix messages and preserve thread updates."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixPlatformEventMessagesSendStreamCoreMixin,
    MatrixPlatformEventMessagesAggregateMixin,
    MatrixPlatformEventMessagesLiveMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixPlatformEventMessagesSendingCoreMixin, _method_name, _method)


__all__ = [
    "MatrixPlatformEventMessagesAggregateMixin",
    "MatrixPlatformEventMessagesLiveMixin",
    "MatrixPlatformEventMessagesSendStreamCoreMixin",
    "MatrixPlatformEventMessagesSendingCoreMixin",
]
