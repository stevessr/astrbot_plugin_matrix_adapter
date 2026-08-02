"""Composable authentication and synchronization mixins."""

from .discovery import AuthDiscoveryMixin
from .login import AuthLoginMixin
from .session import AuthSessionMixin
from .sync import AuthSyncMixin


class AuthMixin(
    AuthDiscoveryMixin,
    AuthLoginMixin,
    AuthSessionMixin,
    AuthSyncMixin,
):
    """Combined Matrix authentication, session, and sync behavior."""

    pass


__all__ = [
    "AuthDiscoveryMixin",
    "AuthLoginMixin",
    "AuthMixin",
    "AuthSessionMixin",
    "AuthSyncMixin",
]
