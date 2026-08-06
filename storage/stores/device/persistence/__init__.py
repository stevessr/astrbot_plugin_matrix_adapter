"""Device storage persistence operations."""

from .backend import MatrixDevicePersistenceBackendMixin
from .delete import MatrixDevicePersistenceDeleteMixin
from .load import MatrixDevicePersistenceLoadMixin
from .save import MatrixDevicePersistenceSaveMixin


class MatrixDevicePersistenceMixin(
    MatrixDevicePersistenceBackendMixin,
    MatrixDevicePersistenceLoadMixin,
    MatrixDevicePersistenceSaveMixin,
    MatrixDevicePersistenceDeleteMixin,
):
    """Persist and validate Matrix device information."""


# Preserve direct method and descriptor attributes expected by
# parent-package __dict__ lookups.
for _mixin in (
    MatrixDevicePersistenceBackendMixin,
    MatrixDevicePersistenceLoadMixin,
    MatrixDevicePersistenceSaveMixin,
    MatrixDevicePersistenceDeleteMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixDevicePersistenceMixin, _method_name, _method)


__all__ = [
    "MatrixDevicePersistenceBackendMixin",
    "MatrixDevicePersistenceDeleteMixin",
    "MatrixDevicePersistenceLoadMixin",
    "MatrixDevicePersistenceMixin",
    "MatrixDevicePersistenceSaveMixin",
]
