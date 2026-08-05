"""Room call-decline and message-edit send operations."""

from .decline import MessageCallDeclineMixin
from .edit import MessageEditSendMixin


class MessageRoomRelationSendMixin(
    MessageCallDeclineMixin,
    MessageEditSendMixin,
):
    """Send call-decline events and edits with Matrix relations."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MessageCallDeclineMixin,
    MessageEditSendMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MessageRoomRelationSendMixin, _method_name, _method)


__all__ = [
    "MessageCallDeclineMixin",
    "MessageEditSendMixin",
    "MessageRoomRelationSendMixin",
]
