"""Layered Matrix authentication login flows."""

from .oauth2 import MatrixAuthOAuth2Mixin
from .password import MatrixAuthPasswordMixin
from .qr import MatrixAuthQrMixin
from .refresh import MatrixAuthRefreshMixin
from .restore import MatrixAuthRestoreMixin
from .sso import MatrixAuthSsoMixin
from .token import MatrixAuthTokenMixin


class MatrixAuthLogin(
    MatrixAuthQrMixin,
    MatrixAuthRestoreMixin,
    MatrixAuthPasswordMixin,
    MatrixAuthTokenMixin,
    MatrixAuthOAuth2Mixin,
    MatrixAuthSsoMixin,
    MatrixAuthRefreshMixin,
):
    """Compose the supported Matrix authentication login flows."""

    pass


__all__ = [
    "MatrixAuthLogin",
    "MatrixAuthOAuth2Mixin",
    "MatrixAuthPasswordMixin",
    "MatrixAuthQrMixin",
    "MatrixAuthRefreshMixin",
    "MatrixAuthRestoreMixin",
    "MatrixAuthSsoMixin",
    "MatrixAuthTokenMixin",
]
