"""Composable Matrix session lifecycle and identity operations."""

from typing import Any  # noqa: F401

from .identity import AuthSessionIdentityMixin
from .lifecycle import AuthSessionLifecycleMixin


class AuthSessionMixin(
    AuthSessionLifecycleMixin,
    AuthSessionIdentityMixin,
):
    """Manage the currently authenticated Matrix session."""

    pass


# Preserve direct method attributes exposed by the former mixin.
AuthSessionMixin.logout = AuthSessionLifecycleMixin.__dict__["logout"]
AuthSessionMixin.logout_all = AuthSessionLifecycleMixin.__dict__["logout_all"]
AuthSessionMixin.restore_login = AuthSessionIdentityMixin.__dict__["restore_login"]
AuthSessionMixin.whoami = AuthSessionIdentityMixin.__dict__["whoami"]
AuthSessionMixin.refresh_access_token = AuthSessionLifecycleMixin.__dict__[
    "refresh_access_token"
]


__all__ = ["Any", "AuthSessionMixin"]
