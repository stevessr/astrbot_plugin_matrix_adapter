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
        """Initialize the Matrix OAuth 2.0 handler.

        ``redirect_uri`` is optional because Matrix v1.18 / MSC4341 allows
        headless clients to use the OAuth Device Authorization Grant instead of
        the browser redirect flow.
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

        # OAuth2 configuration discovered from the homeserver.  Keep the
        # Matrix v1.18 extensions instead of discarding them so callers can use
        # account-management deep links and the device authorization grant.
        self.issuer: str | None = None
        self.authorization_endpoint: str | None = None
        self.token_endpoint: str | None = None
        self.revocation_endpoint: str | None = None
        self.registration_endpoint: str | None = None
        self.device_authorization_endpoint: str | None = None
        self.grant_types_supported: list[str] = []
        self.account_management_uri: str | None = None
        self.account_management_actions_supported: list[str] = []
