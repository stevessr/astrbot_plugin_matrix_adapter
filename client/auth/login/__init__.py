"""Composable Matrix credential login and registration operations."""

from typing import Any  # noqa: F401

from astrbot.api import logger  # noqa: F401

from ....constants import LOGIN_TYPE_PASSWORD, LOGIN_TYPE_TOKEN  # noqa: F401
from .credentials import AuthLoginCredentialsMixin
from .registration import AuthLoginRegistrationMixin


class AuthLoginMixin(
    AuthLoginCredentialsMixin,
    AuthLoginRegistrationMixin,
):
    """Perform Matrix login and registration flows."""

    pass


# Preserve direct method attributes exposed by the former mixin.
AuthLoginMixin.login_password = AuthLoginCredentialsMixin.__dict__["login_password"]
AuthLoginMixin.login_token = AuthLoginCredentialsMixin.__dict__["login_token"]
AuthLoginMixin.register = AuthLoginRegistrationMixin.__dict__["register"]


__all__ = [
    "Any",
    "AuthLoginMixin",
    "LOGIN_TYPE_PASSWORD",
    "LOGIN_TYPE_TOKEN",
    "logger",
]
