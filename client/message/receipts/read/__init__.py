"""Matrix read receipts and read markers."""

from .markers import MessageReadMarkersMixin
from .receipts import MessageReadReceiptsMixin as _MessageReadReceiptsMixin


class MessageReadReceiptsMixin(
    _MessageReadReceiptsMixin,
    MessageReadMarkersMixin,
):
    """Send read receipts and read markers."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    _MessageReadReceiptsMixin,
    MessageReadMarkersMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MessageReadReceiptsMixin, _method_name, _method)


__all__ = [
    "MessageReadMarkersMixin",
    "MessageReadReceiptsMixin",
]
