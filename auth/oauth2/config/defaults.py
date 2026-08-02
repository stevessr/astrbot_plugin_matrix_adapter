"""OAuth2 configuration defaults and scope constants."""


class MatrixOAuth2ConfigDefaultsMixin:
    _OAUTH2_HTTP_TIMEOUT_DEFAULT_SECONDS = 30.0
    _OAUTH2_HTTP_TIMEOUT_MIN_SECONDS = 5.0
    _OAUTH2_HTTP_TIMEOUT_MAX_SECONDS = 120.0
    _STABLE_API_SCOPE = "urn:matrix:client:api:*"
    _LEGACY_API_SCOPE = "urn:matrix:org.matrix.msc2967.client:api:*"
    _STABLE_DEVICE_SCOPE_PREFIX = "urn:matrix:client:device:"
    _LEGACY_DEVICE_SCOPE_PREFIX = "urn:matrix:org.matrix.msc2967.client:device:"
    _DEFAULT_SCOPES = ("openid", _STABLE_API_SCOPE)
