"""Matrix message event conversion.

Public symbols re-exported for backward compatibility.
"""

from .content import MatrixReceiverMessageContentMixin
from .core import MatrixReceiverMessageConvertCoreMixin
from .reply import MatrixReceiverMessageReplyMixin


class MatrixReceiverMessageConvertMixin(
    MatrixReceiverMessageConvertCoreMixin,
    MatrixReceiverMessageReplyMixin,
    MatrixReceiverMessageContentMixin,
):
    """Convert Matrix message events to AstrBot messages."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixReceiverMessageConvertCoreMixin,
    MatrixReceiverMessageReplyMixin,
    MatrixReceiverMessageContentMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixReceiverMessageConvertMixin, _method_name, _method)


__all__ = [
    "MatrixReceiverMessageContentMixin",
    "MatrixReceiverMessageConvertCoreMixin",
    "MatrixReceiverMessageConvertMixin",
    "MatrixReceiverMessageReplyMixin",
]
