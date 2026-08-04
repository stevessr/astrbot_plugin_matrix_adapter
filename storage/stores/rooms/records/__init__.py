"""Composable room member record persistence operations.

Public symbols re-exported for backward compatibility.
"""

from .core import MatrixRoomMemberRecordsCoreMixin
from .diff import MatrixRoomMemberRecordsDiffMixin


class MatrixRoomMemberRecordsMixin(
    MatrixRoomMemberRecordsCoreMixin,
    MatrixRoomMemberRecordsDiffMixin,
):
    """Save room member records."""


# Preserve direct method attributes exposed by the former flat mixin:
# parent packages use __dict__ iteration copies, which miss inherited methods.
for _mixin in (
    MatrixRoomMemberRecordsCoreMixin,
    MatrixRoomMemberRecordsDiffMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixRoomMemberRecordsMixin, _method_name, _method)


__all__ = [
    "MatrixRoomMemberRecordsCoreMixin",
    "MatrixRoomMemberRecordsDiffMixin",
    "MatrixRoomMemberRecordsMixin",
]
