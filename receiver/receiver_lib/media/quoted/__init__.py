"""Quoted media conversion and asynchronous fallback handling.

Public symbols re-exported for backward compatibility.
"""

from .background import MatrixReceiverQuotedBackgroundMixin
from .core import MatrixReceiverQuotedCoreMixin


class MatrixReceiverQuotedMediaMixin(
    MatrixReceiverQuotedCoreMixin,
    MatrixReceiverQuotedBackgroundMixin,
):
    """Append downloaded or remote quoted media components."""


# Preserve direct method attributes exposed by the former mixin.
for _mixin in (
    MatrixReceiverQuotedCoreMixin,
    MatrixReceiverQuotedBackgroundMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixReceiverQuotedMediaMixin, _method_name, _method)


__all__ = [
    "MatrixReceiverQuotedBackgroundMixin",
    "MatrixReceiverQuotedCoreMixin",
    "MatrixReceiverQuotedMediaMixin",
]
