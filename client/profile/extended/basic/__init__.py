"""Basic presence and MSC4133 extended profile operations."""

from .extended import ProfileExtendedFieldsMixin
from .presence import ProfilePresenceMixin


class ProfileBasicMixin(
    ProfilePresenceMixin,
    ProfileExtendedFieldsMixin,
):
    """Presence status and extended profile field operations."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    ProfilePresenceMixin,
    ProfileExtendedFieldsMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(ProfileBasicMixin, _method_name, _method)


__all__ = ["ProfileBasicMixin"]
