"""Matrix platform discovery helpers used by reaction utilities."""

from .access import MatrixUtilsReactionPlatformAccessMixin
from .instances import MatrixUtilsReactionPlatformInstancesMixin
from .selection import MatrixUtilsReactionPlatformSelectionMixin


class MatrixUtilsReactionPlatformMixin(
    MatrixUtilsReactionPlatformInstancesMixin,
    MatrixUtilsReactionPlatformSelectionMixin,
    MatrixUtilsReactionPlatformAccessMixin,
):
    """Find Matrix platform, client, and E2EE instances."""


# Preserve direct staticmethod attributes expected by sibling-module __dict__ lookups.
for _mixin in (
    MatrixUtilsReactionPlatformInstancesMixin,
    MatrixUtilsReactionPlatformSelectionMixin,
    MatrixUtilsReactionPlatformAccessMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixUtilsReactionPlatformMixin, _method_name, _method)


__all__ = [
    "MatrixUtilsReactionPlatformAccessMixin",
    "MatrixUtilsReactionPlatformInstancesMixin",
    "MatrixUtilsReactionPlatformMixin",
    "MatrixUtilsReactionPlatformSelectionMixin",
]
