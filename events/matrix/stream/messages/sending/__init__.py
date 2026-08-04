"""Live Matrix message streaming, split by responsibility.

Public symbols re-exported for backward compatibility.
"""

from .core import MatrixPlatformEventMessagesSendingCoreMixin
from .payload import MatrixPlatformEventMessagesPayloadMixin


class MatrixPlatformEventMessagesSendingMixin(
    MatrixPlatformEventMessagesSendingCoreMixin,
    MatrixPlatformEventMessagesPayloadMixin,
):
    """Send live Matrix messages and preserve thread updates."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixPlatformEventMessagesSendingCoreMixin,
    MatrixPlatformEventMessagesPayloadMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixPlatformEventMessagesSendingMixin, _method_name, _method)


__all__ = [
    "MatrixPlatformEventMessagesSendingMixin",
    "MatrixPlatformEventMessagesSendingCoreMixin",
    "MatrixPlatformEventMessagesPayloadMixin",
]
