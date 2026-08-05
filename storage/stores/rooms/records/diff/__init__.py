"""Room member record field-diff merge logic."""

from .core import MatrixRoomMemberRecordsDiffCoreMixin


class MatrixRoomMemberRecordsDiffMixin(MatrixRoomMemberRecordsDiffCoreMixin):
    """Compare incoming member fields against an existing record."""


# Preserve direct method attributes: parent packages use __dict__ iteration
# copies, which miss inherited methods.
for _mixin in (MatrixRoomMemberRecordsDiffCoreMixin,):
    for _name, _member in _mixin.__dict__.items():
        if isinstance(_member, (staticmethod, classmethod)) or callable(_member):
            setattr(MatrixRoomMemberRecordsDiffMixin, _name, _member)


__all__ = ["MatrixRoomMemberRecordsDiffMixin"]
