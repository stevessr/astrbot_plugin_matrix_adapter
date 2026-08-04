"""Matrix event redaction, reporting, context, and relation operations.

Public symbols re-exported for backward compatibility.
"""

from .modify import MessageEventModifyMixin
from .query import MessageEventQueryMixin


class MessageEventOperationsMixin(
    MessageEventModifyMixin,
    MessageEventQueryMixin,
):
    """Event redaction, reporting, context, and relation queries."""


# Preserve direct method attributes exposed by the former mixin.
for _mixin in (
    MessageEventModifyMixin,
    MessageEventQueryMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MessageEventOperationsMixin, _method_name, _method)


__all__ = [
    "MessageEventModifyMixin",
    "MessageEventOperationsMixin",
    "MessageEventQueryMixin",
]
