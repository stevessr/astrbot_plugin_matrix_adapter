"""Room power-level and role operations."""

from .endpoints import UserPowerLevelEndpointMixin
from .roles import UserPowerLevelRoleMixin


class UserPowerLevelsMixin(
    UserPowerLevelEndpointMixin,
    UserPowerLevelRoleMixin,
):
    """Power-level and role-management helpers."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    UserPowerLevelEndpointMixin,
    UserPowerLevelRoleMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(UserPowerLevelsMixin, _method_name, _method)


__all__ = ["UserPowerLevelsMixin"]
