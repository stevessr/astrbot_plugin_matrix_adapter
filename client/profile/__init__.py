from .account import ProfileAccountMixin
from .extended import ProfileExtendedMixin

__all__ = ["ProfileAccountMixin", "ProfileExtendedMixin"]


class ProfileMixin(
    ProfileAccountMixin,
    ProfileExtendedMixin,
):
    """Combined mixin."""

    pass
