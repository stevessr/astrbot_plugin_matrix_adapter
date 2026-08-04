"""OAuth2 authorization-code login flow."""

from typing import Any

from ...core import _log
from .exchange import _exchange_login_code
from .prepare import _perform_authorization, _prepare_login_client


class MatrixOAuth2FlowLoginMixin:
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
            await _prepare_login_client(self)

            # Step 3: Wait for the authorization callback
            code, pkce_verifier = await _perform_authorization(self, auth_endpoint)

            # Step 4: Exchange code for token
            return await _exchange_login_code(self, token_endpoint, code, pkce_verifier)

        except Exception as e:
            _log("error", f"OAuth2 login failed: {e}")
            raise
        finally:
            if self.callback_server:
                await self.callback_server.stop()
                self.callback_server = None
