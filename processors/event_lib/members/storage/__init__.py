"""Room member storage and profile persistence handlers."""

from .load import MatrixEventProcessorMemberStorageLoadMixin
from .persist import MatrixEventProcessorMemberStoragePersistMixin


class MatrixEventProcessorMemberStorageMixin(
    MatrixEventProcessorMemberStorageLoadMixin,
    MatrixEventProcessorMemberStoragePersistMixin,
):
    """Load room members and persist interacted user profiles."""


# Preserve direct method attributes exposed by the former flat mixin:
# the parent uses Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixEventProcessorMemberStorageLoadMixin,
    MatrixEventProcessorMemberStoragePersistMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(
                MatrixEventProcessorMemberStorageMixin,
                _method_name,
                _method,
            )


__all__ = ["MatrixEventProcessorMemberStorageMixin"]
