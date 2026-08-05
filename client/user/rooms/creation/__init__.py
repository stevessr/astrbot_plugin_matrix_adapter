"""Direct-message and general room creation operations."""

from .dm import UserRoomCreationDirectMixin
from .general import UserRoomCreationGeneralMixin


class UserRoomCreationMixin(
    UserRoomCreationDirectMixin,
    UserRoomCreationGeneralMixin,
):
    """Create direct-message and general Matrix rooms."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    UserRoomCreationDirectMixin,
    UserRoomCreationGeneralMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(UserRoomCreationMixin, _method_name, _method)


__all__ = ["UserRoomCreationMixin"]
