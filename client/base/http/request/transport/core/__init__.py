"""Matrix HTTP request and response handling."""

from .core import MatrixHTTPTransportRequestMixin
from .setup import MatrixHTTPTransportSetupMixin
from .status import MatrixHTTPTransportStatusMixin


class MatrixHTTPTransportCoreMixin(MatrixHTTPTransportRequestMixin):
    """Issue Matrix API requests and normalize failures."""

    pass


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixHTTPTransportRequestMixin,
    MatrixHTTPTransportSetupMixin,
    MatrixHTTPTransportStatusMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if _method_name.startswith("__"):
            continue
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixHTTPTransportCoreMixin, _method_name, _method)


__all__ = [
    "MatrixHTTPTransportCoreMixin",
    "MatrixHTTPTransportRequestMixin",
    "MatrixHTTPTransportSetupMixin",
    "MatrixHTTPTransportStatusMixin",
]
