"""OAuth2 authorization-code and headless device login flow."""

from typing import Any

from ...core import _log
from .exchange import _exchange_login_code
from .prepare import _perform_authorization, _prepare_login_client


class MatrixOAuth2FlowLoginMixin:
    async def login(self) -> dict[str, Any]:
        """Perform OAuth2 login with automatic stable-flow selection.

        Matrix v1.18 / MSC4341 is used automatically when the caller has no
        redirect URI and the homeserver advertises the device authorization
        grant. Existing deployments with an AstrBot webhook keep using the
        authorization-code + PKCE flow unchanged.
        """
        try:
            _log("info", "🔍 Discovering OAuth2 configuration from server...")
            endpoints = await self._discover_oauth_endpoints()

            if not self.redirect_uri:
                if self.supports_device_authorization_grant():
                    _log(
                        "info",
                        "No OAuth redirect URI configured; using Matrix v1.18 device authorization grant",
                    )
                    return await self.login_device()
                raise RuntimeError(
                    "OAuth2 redirect_uri is not configured and the homeserver does not advertise the device authorization grant"
                )

            auth_endpoint = endpoints["authorization_endpoint"]
            token_endpoint = endpoints["token_endpoint"]

            await _prepare_login_client(self)
            code, pkce_verifier = await _perform_authorization(self, auth_endpoint)
            return await _exchange_login_code(self, token_endpoint, code, pkce_verifier)

        except Exception as e:
            _log("error", f"OAuth2 login failed: {e}")
            raise
        finally:
            if self.callback_server:
                await self.callback_server.stop()
                self.callback_server = None
