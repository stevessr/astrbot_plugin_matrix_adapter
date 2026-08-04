"""Matrix platform event send orchestration, split by responsibility.

Public symbols re-exported for backward compatibility.
"""

from ..transport import MatrixPlatformEventTransportMixin
from .core import MatrixPlatformEventSendCoreMixin
from .fc import MatrixPlatformEventSendFcMixin
from .reply import MatrixPlatformEventSendReplyMixin
from .thread import MatrixPlatformEventSendThreadMixin


class MatrixPlatformEventSendMixin(
    MatrixPlatformEventSendCoreMixin,
    MatrixPlatformEventSendFcMixin,
    MatrixPlatformEventSendReplyMixin,
    MatrixPlatformEventSendThreadMixin,
    MatrixPlatformEventTransportMixin,
):
    """Send message chains and resolve Matrix thread/reply context."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixPlatformEventSendCoreMixin,
    MatrixPlatformEventSendFcMixin,
    MatrixPlatformEventSendReplyMixin,
    MatrixPlatformEventSendThreadMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixPlatformEventSendMixin, _method_name, _method)


__all__ = [
    "MatrixPlatformEventSendMixin",
    "MatrixPlatformEventSendCoreMixin",
    "MatrixPlatformEventSendFcMixin",
    "MatrixPlatformEventSendReplyMixin",
    "MatrixPlatformEventSendThreadMixin",
    "MatrixPlatformEventTransportMixin",
]
