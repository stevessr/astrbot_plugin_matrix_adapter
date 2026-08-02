"""Initialize OAuth2 handler state."""

from ..core import OAuth2CallbackServer


class MatrixOAuth2ConfigInitializationMixin:
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
