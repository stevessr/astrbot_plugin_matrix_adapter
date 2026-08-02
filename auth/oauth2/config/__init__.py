"""Composable OAuth2 configuration, device, scope, and timeout helpers."""

import base64
import secrets

from ..core import OAuth2CallbackServer
from .defaults import MatrixOAuth2ConfigDefaultsMixin
from .device import MatrixOAuth2ConfigDeviceMixin
from .initialization import MatrixOAuth2ConfigInitializationMixin
from .scopes import MatrixOAuth2ConfigScopesMixin
from .timeout import MatrixOAuth2ConfigTimeoutMixin


class MatrixOAuth2ConfigMixin(
    MatrixOAuth2ConfigDefaultsMixin,
    MatrixOAuth2ConfigInitializationMixin,
    MatrixOAuth2ConfigDeviceMixin,
    MatrixOAuth2ConfigScopesMixin,
    MatrixOAuth2ConfigTimeoutMixin,
):
    """Initialize OAuth2 state and normalize device/scopes configuration."""

    pass


# Preserve direct constants and method attributes exposed by the former mixin.
for _constant_name in (
    "_OAUTH2_HTTP_TIMEOUT_DEFAULT_SECONDS",
    "_OAUTH2_HTTP_TIMEOUT_MIN_SECONDS",
    "_OAUTH2_HTTP_TIMEOUT_MAX_SECONDS",
    "_STABLE_API_SCOPE",
    "_LEGACY_API_SCOPE",
    "_STABLE_DEVICE_SCOPE_PREFIX",
    "_LEGACY_DEVICE_SCOPE_PREFIX",
    "_DEFAULT_SCOPES",
):
    setattr(
        MatrixOAuth2ConfigMixin,
        _constant_name,
        getattr(MatrixOAuth2ConfigDefaultsMixin, _constant_name),
    )

MatrixOAuth2ConfigMixin.__init__ = MatrixOAuth2ConfigInitializationMixin.__dict__[
    "__init__"
]
MatrixOAuth2ConfigMixin._normalize_device_id = staticmethod(
    MatrixOAuth2ConfigDeviceMixin.__dict__["_normalize_device_id"].__func__
)
MatrixOAuth2ConfigMixin._generate_device_id = MatrixOAuth2ConfigDeviceMixin.__dict__[
    "_generate_device_id"
]
MatrixOAuth2ConfigMixin._ensure_device_id = MatrixOAuth2ConfigDeviceMixin.__dict__[
    "_ensure_device_id"
]
MatrixOAuth2ConfigMixin._normalize_scopes = MatrixOAuth2ConfigScopesMixin.__dict__[
    "_normalize_scopes"
]
MatrixOAuth2ConfigMixin._resolve_oauth_http_timeout_seconds = (
    MatrixOAuth2ConfigTimeoutMixin.__dict__["_resolve_oauth_http_timeout_seconds"]
)


__all__ = [
    "MatrixOAuth2ConfigMixin",
    "OAuth2CallbackServer",
    "base64",
    "secrets",
]
