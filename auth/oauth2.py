"""
Matrix OAuth2 Authentication Module
Implements OAuth2 authentication flow with HTTP callback server
"""

import asyncio
import logging
import secrets
from typing import Any
from urllib.parse import urlencode

import aiohttp
from aiohttp import web

logger = logging.getLogger("astrbot.matrix.oauth2")


def _log(level: str, msg: str):
    """
    Helper function to log messages with required AstrBot extra fields

    Args:
        level: Log level (info, error, warning, debug)
        msg: Log message
    """
    extra = {"plugin_tag": "matrix", "short_levelname": level[:4].upper()}
    if level == "info":
        logger.info(msg, extra=extra)
    elif level == "error":
        logger.error(msg, extra=extra)
    elif level == "warning":
        logger.warning(msg, extra=extra)
    elif level == "debug":
        logger.debug(msg, extra=extra)


class OAuth2CallbackServer:
    """
    HTTP server for handling OAuth2 callbacks
    Listens on localhost for the OAuth2 redirect
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8765):
        """
        Initialize OAuth2 callback server

        Args:
            host: Host to bind to (default: 127.0.0.1)
            port: Port to listen on (default: 8765)
        """
        self.host = host
        self.port = port
        self.app = web.Application()
        self.runner: web.AppRunner | None = None
        self.site: web.TCPSite | None = None
        self.callback_future: asyncio.Future | None = None
        self.state: str | None = None

        # Setup routes
        self.app.router.add_get("/callback", self._handle_callback)
        self.app.router.add_get("/", self._handle_root)

    async def _handle_root(self, request: web.Request) -> web.Response:
        """Handle root path"""
        return web.Response(
            text="Matrix OAuth2 Authentication Server\nWaiting for OAuth2 callback...",
            content_type="text/plain",
        )

    async def _handle_callback(self, request: web.Request) -> web.Response:
        """
        Handle OAuth2 callback

        Args:
            request: HTTP request

        Returns:
            HTTP response
        """
        try:
            # Extract query parameters
            query_params = request.query

            # Check for error
            if "error" in query_params:
                error = query_params.get("error")
                error_description = query_params.get("error_description", "")
                _log("error", f"OAuth2 error: {error} - {error_description}")

                if self.callback_future and not self.callback_future.done():
                    self.callback_future.set_exception(
                        Exception(f"OAuth2 error: {error} - {error_description}")
                    )

                return web.Response(
                    text=f"Authentication failed: {error}\n{error_description}",
                    status=400,
                )

            # Verify state parameter
            state = query_params.get("state")
            if state != self.state:
                _log("error", "State mismatch in OAuth2 callback")
                if self.callback_future and not self.callback_future.done():
                    self.callback_future.set_exception(
                        Exception("State mismatch in OAuth2 callback")
                    )
                return web.Response(text="State mismatch", status=400)

            # Extract authorization code
            code = query_params.get("code")
            if not code:
                _log("error", "No authorization code in OAuth2 callback")
                if self.callback_future and not self.callback_future.done():
                    self.callback_future.set_exception(
                        Exception("No authorization code received")
                    )
                return web.Response(text="No authorization code", status=400)

            # Set the result
            if self.callback_future and not self.callback_future.done():
                self.callback_future.set_result(code)

            return web.Response(
                text="Authentication successful! You can close this window.",
                content_type="text/plain",
            )

        except Exception as e:
            _log("error", f"Error handling OAuth2 callback: {e}")
            if self.callback_future and not self.callback_future.done():
                self.callback_future.set_exception(e)
            return web.Response(text=f"Error: {str(e)}", status=500)

    async def start(self) -> str:
        """
        Start the callback server

        Returns:
            The callback URL
        """
        try:
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()
            self.site = web.TCPSite(self.runner, self.host, self.port)
            await self.site.start()

            callback_url = f"http://{self.host}:{self.port}/callback"
            _log("info", f"OAuth2 callback server started at {callback_url}")
            return callback_url

        except Exception as e:
            _log("error", f"Failed to start OAuth2 callback server: {e}")
            raise

    async def stop(self):
        """Stop the callback server"""
        try:
            if self.site:
                await self.site.stop()
            if self.runner:
                await self.runner.cleanup()
            _log("info", "OAuth2 callback server stopped")
        except Exception as e:
            _log("error", f"Error stopping OAuth2 callback server: {e}")

    async def wait_for_callback(self, state: str, timeout: int = 300) -> str:
        """
        Wait for OAuth2 callback

        Args:
            state: State parameter for CSRF protection
            timeout: Timeout in seconds (default: 300)

        Returns:
            Authorization code

        Raises:
            asyncio.TimeoutError: If timeout is reached
            Exception: If callback fails
        """
        self.state = state
        self.callback_future = asyncio.Future()

        try:
            code = await asyncio.wait_for(self.callback_future, timeout=timeout)
            return code
        except asyncio.TimeoutError:
            _log("error", "OAuth2 callback timeout")
            raise
        finally:
            self.callback_future = None
            self.state = None


class MatrixOAuth2:
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

    async def _discover_oauth_endpoints(self) -> dict[str, Any]:
        """
        Discover OAuth2 configuration from Matrix homeserver

        This method follows the Matrix specification for OAuth2 discovery:
        1. Fetch /.well-known/matrix/client
        2. Extract m.authentication.issuer
        3. Fetch issuer's /.well-known/openid-configuration
        4. Extract OAuth2 endpoints and configuration

        Returns:
            Dictionary with OAuth2 configuration including:
            - issuer
            - authorization_endpoint
            - token_endpoint
            - registration_endpoint (optional)
            - account (optional)
            - client_id (if provided by server)

        Raises:
            Exception: If discovery fails or server doesn't support OAuth2
        """
        try:
            _log("info", f"Discovering OAuth2 configuration from {self.homeserver}")

            # Step 1: Get Matrix client well-known
            async with aiohttp.ClientSession() as session:
                well_known_url = f"{self.homeserver}/.well-known/matrix/client"
                _log("debug", f"Fetching {well_known_url}")

                async with session.get(well_known_url) as response:
                    if response.status == 404:
                        raise Exception(
                            "Server does not have /.well-known/matrix/client endpoint. "
                            "OAuth2 authentication is not supported by this homeserver. "
                            "Please use 'password' or 'token' authentication instead."
                        )
                    elif response.status != 200:
                        raise Exception(
                            f"Failed to fetch well-known: HTTP {response.status}"
                        )

                    well_known_data = await response.json()
                    _log("debug", f"Well-known data: {well_known_data}")

                    # Extract authentication configuration
                    # Try standard m.authentication first
                    auth_config = well_known_data.get("m.authentication", {})

                    # If not found, try MSC4143 (new standard)
                    if not auth_config:
                        auth_config = well_known_data.get(
                            "org.matrix.msc4143.authentication", {}
                        )

                    # If still not found, try MSC2965 (matrix.org uses this)
                    if not auth_config:
                        auth_config = well_known_data.get(
                            "org.matrix.msc2965.authentication", {}
                        )

                    if not auth_config:
                        _log(
                            "error",
                            "❌ Failed to discover OAuth2 configuration: No authentication configuration found in well-known.",
                        )
                        _log(
                            "error",
                            "💡 This homeserver does not support OAuth2 authentication.",
                        )
                        _log(
                            "error",
                            "💡 Please change matrix_auth_method to 'password' or 'token' in your configuration.",
                        )
                        _log(
                            "debug",
                            f"Available keys in well-known: {list(well_known_data.keys())}",
                        )
                        _log(
                            "debug",
                            "Authentication keys checked: m.authentication, org.matrix.msc4143.authentication, org.matrix.msc2965.authentication",
                        )
                        raise Exception(
                            "No authentication configuration found in well-known. "
                            "OAuth2 authentication is not supported by this homeserver. "
                            "Please use 'password' or 'token' authentication instead."
                        )

                    # Get issuer URL
                    issuer = auth_config.get("issuer")
                    if not issuer:
                        raise Exception(
                            "No issuer found in m.authentication. "
                            "OAuth2 authentication is not properly configured on this homeserver. "
                            "Please use 'password' or 'token' authentication instead."
                        )

                    self.issuer = issuer
                    _log("info", f"Found OAuth2 issuer: {issuer}")

                    # Extract account management URI if available
                    account = auth_config.get("account")
                    if account:
                        self.account_management_uri = account
                        _log("info", f"Account management URI: {account}")

                    # Step 2: Get OIDC configuration from issuer
                    # Ensure issuer URL ends with /
                    if not issuer.endswith("/"):
                        issuer = issuer + "/"

                    oidc_config_url = f"{issuer}.well-known/openid-configuration"
                    _log("debug", f"Fetching OIDC configuration from {oidc_config_url}")

                    async with session.get(oidc_config_url) as oidc_response:
                        if oidc_response.status != 200:
                            _log(
                                "error",
                                f"Failed to fetch OIDC configuration: HTTP {oidc_response.status}",
                            )
                            _log("error", f"URL requested: {oidc_config_url}")
                            # Try to get response body for debugging
                            try:
                                error_text = await oidc_response.text()
                                _log("error", f"Response body: {error_text[:200]}")
                            except Exception:
                                pass
                            raise Exception(
                                f"Failed to fetch OIDC configuration: HTTP {oidc_response.status}"
                            )

                        oidc_config = await oidc_response.json()
                        _log("debug", f"OIDC configuration: {oidc_config}")

                        # Extract endpoints
                        self.authorization_endpoint = oidc_config.get(
                            "authorization_endpoint"
                        )
                        self.token_endpoint = oidc_config.get("token_endpoint")
                        self.registration_endpoint = oidc_config.get(
                            "registration_endpoint"
                        )

                        if not self.authorization_endpoint or not self.token_endpoint:
                            raise Exception(
                                "Missing required endpoints in OIDC configuration"
                            )

                        _log("info", "✅ OAuth2 discovery successful!")
                        _log(
                            "info",
                            f"  Authorization endpoint: {self.authorization_endpoint}",
                        )
                        _log("info", f"  Token endpoint: {self.token_endpoint}")
                        if self.registration_endpoint:
                            _log(
                                "info",
                                f"  Registration endpoint: {self.registration_endpoint}",
                            )

                        # Return configuration
                        return {
                            "issuer": self.issuer,
                            "authorization_endpoint": self.authorization_endpoint,
                            "token_endpoint": self.token_endpoint,
                            "registration_endpoint": self.registration_endpoint,
                            "account": self.account_management_uri,
                        }

        except Exception as e:
            error_msg = str(e)
            _log("error", f"❌ Failed to discover OAuth2 configuration: {error_msg}")

            # Provide helpful guidance based on the error
            if "404" in error_msg or "not supported" in error_msg.lower():
                _log(
                    "error",
                    "💡 This homeserver does not support OAuth2 authentication. "
                    "Please change matrix_auth_method to 'password' or 'token' in your configuration.",
                )
            else:
                _log(
                    "error",
                    "Please ensure your Matrix homeserver supports OAuth2/OIDC authentication. "
                    "Check the server's /.well-known/matrix/client endpoint.",
                )
            raise

    def _generate_state(self) -> str:
        """Generate random state for CSRF protection"""
        return secrets.token_urlsafe(32)

    def _generate_pkce_verifier(self) -> str:
        """Generate PKCE code verifier"""
        return secrets.token_urlsafe(64)

    def _generate_pkce_challenge(self, verifier: str) -> str:
        """
        Generate PKCE code challenge from verifier

        Args:
            verifier: PKCE code verifier

        Returns:
            PKCE code challenge (base64url-encoded SHA256 hash)
        """
        import base64
        import hashlib

        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        return challenge

    async def _register_client(self, redirect_uri: str) -> dict[str, str]:
        """
        Dynamically register OAuth2 client with the server

        Uses RFC 7591 Dynamic Client Registration if supported by the server

        Args:
            redirect_uri: The redirect URI to register

        Returns:
            Dictionary with client_id and optionally client_secret

        Raises:
            Exception: If registration fails or is not supported
        """
        if not self.registration_endpoint:
            raise Exception(
                "Dynamic client registration not supported by this server. "
                "Please provide a client_id manually."
            )

        try:
            _log("info", f"Registering OAuth2 client with {self.registration_endpoint}")

            # Prepare registration request
            registration_data = {
                "client_name": "AstrBot Matrix Client",
                "client_uri": "https://github.com/Soulter/AstrBot",
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",  # Public client (PKCE)
                "application_type": "native",
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.registration_endpoint,
                    json=registration_data,
                    headers={"Content-Type": "application/json"},
                ) as response:
                    if response.status not in [200, 201]:
                        error_text = await response.text()
                        raise Exception(
                            f"Client registration failed: HTTP {response.status} - {error_text}"
                        )

                    registration_response = await response.json()

                    client_id = registration_response.get("client_id")
                    client_secret = registration_response.get("client_secret")

                    if not client_id:
                        raise Exception("No client_id in registration response")

                    _log("info", f"✅ Successfully registered client: {client_id}")

                    return {
                        "client_id": client_id,
                        "client_secret": client_secret,
                    }

        except Exception as e:
            _log("error", f"❌ Failed to register OAuth2 client: {e}")
            raise

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
                _log("info", "Starting local OAuth2 callback server...")
                self.callback_server = OAuth2CallbackServer()
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
                code = input().strip()

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
                async with session.post(token_endpoint, json=token_data) as response:
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
                async with session.post(token_endpoint, json=token_data) as response:
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
