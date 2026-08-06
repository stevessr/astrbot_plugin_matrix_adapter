"""Device ID generation and lifecycle operations."""

from .acquire import MatrixDeviceIdentityAcquireMixin
from .generate import MatrixDeviceIdentityGenerateMixin


class MatrixDeviceIdentityMixin(
    MatrixDeviceIdentityAcquireMixin,
    MatrixDeviceIdentityGenerateMixin,
):
    """Generate, load, and rotate Matrix device IDs."""


# Preserve direct method attributes expected by parent-package __dict__ lookups.
for _mixin in (
    MatrixDeviceIdentityAcquireMixin,
    MatrixDeviceIdentityGenerateMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixDeviceIdentityMixin, _method_name, _method)


__all__ = [
    "MatrixDeviceIdentityAcquireMixin",
    "MatrixDeviceIdentityGenerateMixin",
    "MatrixDeviceIdentityMixin",
]
