"""Matrix password and token login operations."""

from .core import AuthLoginCredentialsOrchestratorMixin
from .password import AuthLoginCredentialsPasswordMixin
from .request import AuthLoginCredentialsRequestMixin
from .token import AuthLoginCredentialsTokenMixin


class AuthLoginCredentialsMixin(
    AuthLoginCredentialsOrchestratorMixin,
    AuthLoginCredentialsPasswordMixin,
    AuthLoginCredentialsRequestMixin,
    AuthLoginCredentialsTokenMixin,
):
    """Perform Matrix password and token login flows."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    AuthLoginCredentialsOrchestratorMixin,
    AuthLoginCredentialsPasswordMixin,
    AuthLoginCredentialsRequestMixin,
    AuthLoginCredentialsTokenMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(AuthLoginCredentialsMixin, _method_name, _method)


__all__ = ["AuthLoginCredentialsMixin"]
