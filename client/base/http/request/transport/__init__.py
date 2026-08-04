"""Matrix HTTP request and response handling.

Public symbols re-exported for backward compatibility.
"""

from .core import MatrixHTTPTransportCoreMixin
from .response import MatrixHTTPTransportResponseMixin
from .retry import MatrixHTTPTransportRetryMixin


class MatrixHTTPTransportMixin(
    MatrixHTTPTransportCoreMixin,
    MatrixHTTPTransportRetryMixin,
    MatrixHTTPTransportResponseMixin,
):
    """Issue Matrix API requests and normalize failures."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixHTTPTransportCoreMixin,
    MatrixHTTPTransportRetryMixin,
    MatrixHTTPTransportResponseMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixHTTPTransportMixin, _method_name, _method)


__all__ = [
    "MatrixHTTPTransportCoreMixin",
    "MatrixHTTPTransportMixin",
    "MatrixHTTPTransportResponseMixin",
    "MatrixHTTPTransportRetryMixin",
]
