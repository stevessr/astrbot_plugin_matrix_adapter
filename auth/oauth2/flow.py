"""OAuth2 authorization-code login and token refresh operations."""

from typing import Any
from urllib.parse import urlencode

import aiohttp

from .core import OAuth2CallbackServer, _log


class MatrixOAuth2FlowMixin:
    """Run browser authorization, webhook callbacks, and token refresh."""

    async def login(self) -> dict[str, Any]:
        """
        Perform OAuth2 login flow with automatic server discovery

        This method:
        1. Discovers OAuth2 configuration from the homeserver
        2. Registers a client if no client_id is provided (if supported)
        3. Arms the AstrBot unified webhook callback listener
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

            # Step 2: Arm unified webhook callback receiver
            if not self.redirect_uri:
                raise RuntimeError(
                    "Matrix OAuth2 requires AstrBot unified webhook redirect_uri"
                )
            self.callback_server = OAuth2CallbackServer(self.redirect_uri)
            self.redirect_uri = await self.callback_server.start()
            _log("info", f"OAuth2 callback URL: {self.redirect_uri}")

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
            if self.callback_server:
                self.callback_server.prepare_callback(expected_state=state)

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
            _log("info", f"Please open this URL in your browser:\n\n {auth_url} \n")
            _log("info", "Waiting for authentication...")
            _log("info", "=" * 60)

            code = await self.callback_server.wait_for_callback()

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

            token_timeout_seconds = self._resolve_oauth_http_timeout_seconds(
                cap_seconds=self._OAUTH2_HTTP_TIMEOUT_MAX_SECONDS
            )
            token_timeout = aiohttp.ClientTimeout(total=token_timeout_seconds)
            async with aiohttp.ClientSession(timeout=token_timeout) as session:
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
            self.device_id = whoami.get("device_id") or self.device_id

            _log("info", f"OAuth2 login successful: {whoami.get('user_id')}")

            return {
                "access_token": self.access_token,
                "refresh_token": self.refresh_token,
                "user_id": whoami.get("user_id"),
                "device_id": self.device_id,
                "token_type": self.token_type,
                "expires_in": self.expires_in,
            }

        except Exception as e:
            _log("error", f"OAuth2 login failed: {e}")
            raise
        finally:
            if self.callback_server:
                await self.callback_server.stop()
                self.callback_server = None

    async def handle_webhook_callback(self, request):
        if not self.callback_server:
            return "OAuth2 flow is not ready, please retry.", 503
        return await self.callback_server.handle_callback(request)

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

            token_timeout_seconds = self._resolve_oauth_http_timeout_seconds(
                cap_seconds=self._OAUTH2_HTTP_TIMEOUT_MAX_SECONDS
            )
            token_timeout = aiohttp.ClientTimeout(total=token_timeout_seconds)
            async with aiohttp.ClientSession(timeout=token_timeout) as session:
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
