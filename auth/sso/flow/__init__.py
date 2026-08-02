"""Composable Matrix SSO login, callback, and state helpers."""

import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ....constants import LOGIN_TYPE_SSO
from ...oauth2.core import _log  # noqa: F401
from ..callback import SSOCallbackServer
from ..qr import _build_terminal_qr  # noqa: F401
from .callback import MatrixSSOCallbackMixin
from .login import MatrixSSOLoginMixin
from .state import _attach_state_param  # noqa: F401


class MatrixSSO(MatrixSSOLoginMixin, MatrixSSOCallbackMixin):
    pass


# Preserve direct method attributes exposed by the former SSO flow class.
MatrixSSO.__init__ = MatrixSSOLoginMixin.__dict__["__init__"]
MatrixSSO.login = MatrixSSOLoginMixin.__dict__["login"]
MatrixSSO.handle_webhook_callback = MatrixSSOCallbackMixin.__dict__[
    "handle_webhook_callback"
]


__all__ = [
    "LOGIN_TYPE_SSO",
    "MatrixSSO",
    "SSOCallbackServer",
    "parse_qsl",
    "secrets",
    "urlencode",
    "urlparse",
    "urlunparse",
]
