"""Sync response event routing.

Public symbols re-exported for backward compatibility.
"""

from .core import MatrixSyncManagerEventRoutingCoreMixin
from .fields import MatrixSyncManagerEventRoutingFieldsMixin
from .rooms import MatrixSyncManagerEventRoutingRoomsMixin


class MatrixSyncManagerEventRoutingMixin(
    MatrixSyncManagerEventRoutingCoreMixin,
    MatrixSyncManagerEventRoutingFieldsMixin,
    MatrixSyncManagerEventRoutingRoomsMixin,
):
    """Dispatch sync response fields to registered callbacks."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixSyncManagerEventRoutingCoreMixin,
    MatrixSyncManagerEventRoutingFieldsMixin,
    MatrixSyncManagerEventRoutingRoomsMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixSyncManagerEventRoutingMixin, _method_name, _method)


__all__ = [
    "MatrixSyncManagerEventRoutingCoreMixin",
    "MatrixSyncManagerEventRoutingFieldsMixin",
    "MatrixSyncManagerEventRoutingMixin",
    "MatrixSyncManagerEventRoutingRoomsMixin",
]
