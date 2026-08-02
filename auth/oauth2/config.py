"""OAuth2 handler configuration, scope normalization, and timeout policy."""

import base64
import secrets

from .core import OAuth2CallbackServer


class MatrixOAuth2ConfigMixin:
    """Initialize OAuth2 state and normalize device/scopes configuration."""

    _OAUTH2_HTTP_TIMEOUT_DEFAULT_SECONDS = 30.0
    _OAUTH2_HTTP_TIMEOUT_MIN_SECONDS = 5.0
    _OAUTH2_HTTP_TIMEOUT_MAX_SECONDS = 120.0
    _STABLE_API_SCOPE = "urn:matrix:client:api:*"
    _LEGACY_API_SCOPE = "urn:matrix:org.matrix.msc2967.client:api:*"
    _STABLE_DEVICE_SCOPE_PREFIX = "urn:matrix:client:device:"
    _LEGACY_DEVICE_SCOPE_PREFIX = "urn:matrix:org.matrix.msc2967.client:device:"
    _DEFAULT_SCOPES = ("openid", _STABLE_API_SCOPE)

    def __init__(
        self,
        client,
        homeserver: str,
        client_id: str | None = None,
        client_secret: str | None = None,
        redirect_uri: str | None = None,
        scopes: list | None = None,
        device_id: str | None = None,
    ):
        """
        Initialize OAuth2 handler

        Args:
            client: Matrix HTTP client
            homeserver: Matrix homeserver URL
            client_id: OAuth2 client ID (optional, will be discovered from server if not provided)
            client_secret: OAuth2 client secret (optional for PKCE)
            redirect_uri: OAuth2 redirect URI (required, provided by AstrBot unified webhook)
            scopes: OAuth2 scopes (default: stable Matrix API scope + device scope)
            device_id: Preferred Matrix device ID for stable device scope
        """
        self.client = client
        self.homeserver = homeserver.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.device_id = self._normalize_device_id(device_id)
        self.scopes = self._normalize_scopes(scopes)

        self.callback_server: OAuth2CallbackServer | None = None
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.token_type: str | None = None
        self.expires_in: int | None = None

        # OAuth2 configuration discovered from server
        self.issuer: str | None = None
        self.authorization_endpoint: str | None = None
        self.token_endpoint: str | None = None
        self.registration_endpoint: str | None = None
        self.account_management_uri: str | None = None

    @staticmethod
    def _normalize_device_id(device_id: str | None) -> str | None:
        if not isinstance(device_id, str):
            return None
        normalized = device_id.strip()
        return normalized or None

    def _generate_device_id(self) -> str:
        random_bytes = secrets.token_bytes(9)
        device_id = base64.b64encode(random_bytes).decode("ascii").rstrip("=")
        device_id = device_id.replace("+", "").replace("/", "")

        if len(device_id) < 10:
            device_id += secrets.token_urlsafe(5)[: 15 - len(device_id)]
        elif len(device_id) > 15:
            device_id = device_id[:15]

        return device_id

    def _ensure_device_id(self) -> str:
        if not self.device_id:
            self.device_id = self._generate_device_id()
        return self.device_id

    def _normalize_scopes(self, scopes: list | None) -> list[str]:
        normalized_scopes: list[str] = []
        seen: set[str] = set()
        effective_device_id = self.device_id

        raw_scopes = scopes if scopes is not None else list(self._DEFAULT_SCOPES)
        for scope in raw_scopes:
            if not isinstance(scope, str):
                continue

            normalized_scope = scope.strip()
            if not normalized_scope:
                continue

            if normalized_scope == self._LEGACY_API_SCOPE:
                normalized_scope = self._STABLE_API_SCOPE

            if normalized_scope.startswith(self._LEGACY_DEVICE_SCOPE_PREFIX):
                if not effective_device_id:
                    effective_device_id = self._normalize_device_id(
                        normalized_scope.removeprefix(self._LEGACY_DEVICE_SCOPE_PREFIX)
                    )
                continue

            if normalized_scope.startswith(self._STABLE_DEVICE_SCOPE_PREFIX):
                if not effective_device_id:
                    effective_device_id = self._normalize_device_id(
                        normalized_scope.removeprefix(self._STABLE_DEVICE_SCOPE_PREFIX)
                    )
                continue

            if normalized_scope not in seen:
                normalized_scopes.append(normalized_scope)
                seen.add(normalized_scope)

        self.device_id = self._normalize_device_id(effective_device_id)
        device_scope = f"{self._STABLE_DEVICE_SCOPE_PREFIX}{self._ensure_device_id()}"
        if device_scope not in seen:
            normalized_scopes.append(device_scope)

        return normalized_scopes

    def _resolve_oauth_http_timeout_seconds(
        self, *, cap_seconds: float | None = None
    ) -> float:
        timeout_seconds = self._OAUTH2_HTTP_TIMEOUT_DEFAULT_SECONDS
        get_timeout = getattr(self.client, "get_http_timeout_seconds", None)
        if callable(get_timeout):
            try:
                timeout_seconds = float(get_timeout())
            except Exception:
                timeout_seconds = self._OAUTH2_HTTP_TIMEOUT_DEFAULT_SECONDS

        if timeout_seconds < self._OAUTH2_HTTP_TIMEOUT_MIN_SECONDS:
            timeout_seconds = self._OAUTH2_HTTP_TIMEOUT_MIN_SECONDS

        hard_cap = self._OAUTH2_HTTP_TIMEOUT_MAX_SECONDS
        if cap_seconds is not None:
            try:
                hard_cap = min(
                    hard_cap,
                    max(self._OAUTH2_HTTP_TIMEOUT_MIN_SECONDS, float(cap_seconds)),
                )
            except Exception:
                hard_cap = self._OAUTH2_HTTP_TIMEOUT_MAX_SECONDS

        return min(timeout_seconds, hard_cap)
