"""
Matrix OAuth2 Authentication Module
Implements OAuth2 authentication flow with HTTP callback server
"""

from typing import Any
from urllib.parse import urlencode

import aiohttp

from .oauth2_core import OAuth2CallbackServer, _log
from .oauth2_discovery import MatrixOAuth2Discovery
from .oauth2_pkce import MatrixOAuth2PKCE


class MatrixOAuth2(MatrixOAuth2Discovery, MatrixOAuth2PKCE):
    """
    Matrix OAuth2 Authentication Handler
    Implements the OAuth2 authorization code grant flow with automatic server discovery
    """

    def __init__(
        self,
        client,
        homeserver: str,
        client_id: str | None = None,
        client_secret: str | None = None,
        redirect_uri: str | None = None,
        scopes: list | None = None,
        callback_port: int = 8765,
        callback_host: str = "127.0.0.1",
    ):
        """
        Initialize OAuth2 handler

        Args:
            client: Matrix HTTP client
            homeserver: Matrix homeserver URL
            client_id: OAuth2 client ID (optional, will be discovered from server if not provided)
            client_secret: OAuth2 client secret (optional for PKCE)
            redirect_uri: OAuth2 redirect URI (optional, will use callback server)
            scopes: OAuth2 scopes (default: ["openid", "urn:matrix:org.matrix.msc2967.client:api:*"])
            callback_port: OAuth2 callback server port (default: 8765)
            callback_host: OAuth2 callback server host (default: 127.0.0.1)
        """
        self.client = client
        self.homeserver = homeserver.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes or [
            "openid",
            "urn:matrix:org.matrix.msc2967.client:api:*",
        ]
        self.callback_port = callback_port
        self.callback_host = callback_host

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


    async def login(self) -> dict[str, Any]:
        """
        Perform OAuth2 login flow with automatic server discovery

        This method:
        1. Discovers OAuth2 configuration from the homeserver
        2. Registers a client if no client_id is provided (if supported)
        3. Starts a local callback server if needed
        4. Initiates the OAuth2 authorization code flow with PKCE
        5. Exchanges the authorization code for tokens

        Returns:
            Login response with access_token, user_id, device_id, etc.

        Raises:
            Exception: If login fails
        """
        try:
            # Step 1: Discover OAuth2 configuration
            _log("info", "🔍 Discovering OAuth2 configuration from server...")
            endpoints = await self._discover_oauth_endpoints()
            auth_endpoint = endpoints["authorization_endpoint"]
            token_endpoint = endpoints["token_endpoint"]

            # Step 2: Start callback server if no redirect URI provided
            if not self.redirect_uri:
                _log(
                    "info",
                    f"Starting OAuth2 callback server on {self.callback_host}:{self.callback_port}...",
                )
                self.callback_server = OAuth2CallbackServer(
                    host=self.callback_host, port=self.callback_port
                )
                self.redirect_uri = await self.callback_server.start()
                _log("info", f"Callback server listening at {self.redirect_uri}")

            # Step 3: Register client if no client_id provided
            if not self.client_id:
                _log(
                    "info",
                    "No client_id provided, attempting dynamic client registration...",
                )
                try:
                    registration = await self._register_client(self.redirect_uri)
                    self.client_id = registration["client_id"]
                    self.client_secret = registration.get("client_secret")
                    _log("info", f"✅ Registered as client: {self.client_id}")
                except Exception as e:
                    _log("error", f"Dynamic registration failed: {e}")
                    raise Exception(
                        "No client_id provided and dynamic registration failed. "
                        "Please provide a client_id in the configuration."
                    )

            # Step 4: Generate state and PKCE parameters
            state = self._generate_state()
            pkce_verifier = self._generate_pkce_verifier()
            pkce_challenge = self._generate_pkce_challenge(pkce_verifier)

            # Build authorization URL
            auth_params = {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": " ".join(self.scopes),
                "state": state,
                "code_challenge": pkce_challenge,
                "code_challenge_method": "S256",
            }
            auth_url = f"{auth_endpoint}?{urlencode(auth_params)}"

            _log("info", "=" * 60)
            _log("info", "OAuth2 Authentication Required")
            _log("info", "=" * 60)
            _log("info", f"Please open this URL in your browser:\n\n{auth_url}\n")
            _log("info", "Waiting for authentication...")
            _log("info", "=" * 60)

            # Wait for callback
            if self.callback_server:
                code = await self.callback_server.wait_for_callback(state)
            else:
                # Manual code entry (for custom redirect URIs)
                _log("info", "Enter the authorization code:")
                _log("info", "⚠️  Manual code entry is not supported in async context.")
                _log(
                    "info", "Please use the callback server or provide a redirect_uri."
                )
                raise RuntimeError(
                    "Manual code entry not supported in async context. "
                    "Either use the callback server (don't provide redirect_uri) "
                    "or implement your own async input method."
                )

            # Exchange code for token
            token_data = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "code_verifier": pkce_verifier,
            }

            if self.client_secret:
                token_data["client_secret"] = self.client_secret

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    token_endpoint,
                    data=urlencode(token_data),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise Exception(f"Token exchange failed: {error_text}")

                    token_response = await response.json()

            # Extract tokens
            self.access_token = token_response.get("access_token")
            self.refresh_token = token_response.get("refresh_token")
            self.token_type = token_response.get("token_type", "Bearer")
            self.expires_in = token_response.get("expires_in")

            # Set access token in client
            self.client.access_token = self.access_token

            # Get user info
            whoami = await self.client.whoami()

            _log("info", f"OAuth2 login successful: {whoami.get('user_id')}")

            return {
                "access_token": self.access_token,
                "refresh_token": self.refresh_token,
                "user_id": whoami.get("user_id"),
                "device_id": whoami.get("device_id"),
                "token_type": self.token_type,
                "expires_in": self.expires_in,
            }

        except Exception as e:
            _log("error", f"OAuth2 login failed: {e}")
            raise
        finally:
            # Stop callback server
            if self.callback_server:
                await self.callback_server.stop()
                self.callback_server = None

    async def refresh_access_token(self) -> dict[str, Any]:
        """
        Refresh access token using refresh token

        Returns:
            New token response

        Raises:
            Exception: If refresh fails
        """
        if not self.refresh_token:
            raise Exception("No refresh token available")

        try:
            endpoints = await self._discover_oauth_endpoints()
            token_endpoint = endpoints["token_endpoint"]

            token_data = {
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token,
                "client_id": self.client_id,
            }

            if self.client_secret:
                token_data["client_secret"] = self.client_secret

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    token_endpoint,
                    data=urlencode(token_data),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise Exception(f"Token refresh failed: {error_text}")

                    token_response = await response.json()

            # Update tokens
            self.access_token = token_response.get("access_token")
            if "refresh_token" in token_response:
                self.refresh_token = token_response["refresh_token"]
            self.expires_in = token_response.get("expires_in")

            # Update client
            self.client.access_token = self.access_token

            _log("info", "Access token refreshed successfully")

            return token_response

        except Exception as e:
            _log("error", f"Failed to refresh access token: {e}")
            raise
