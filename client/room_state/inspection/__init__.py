"""Room state inspection and initial-sync operations."""

from .endpoints import RoomStateInspectionEndpointMixin
from .sync import RoomStateInspectionSyncMixin


class RoomStateInspectionMixin(
    RoomStateInspectionEndpointMixin,
    RoomStateInspectionSyncMixin,
):
    """Read-only room state and timeline inspection helpers."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    RoomStateInspectionEndpointMixin,
    RoomStateInspectionSyncMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(RoomStateInspectionMixin, _method_name, _method)


__all__ = ["RoomStateInspectionMixin"]
