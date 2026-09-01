"""Matrix SSO login flow."""

import secrets
from urllib.parse import urlencode

from ...callback import SSOCallbackServer
from .display import MatrixSSOLoginDisplayMixin
from .flows import MatrixSSOLoginFlowsMixin
from .server import MatrixSSOLoginServerMixin


class MatrixSSOLoginMixin(
    MatrixSSOLoginFlowsMixin,
    MatrixSSOLoginServerMixin,
    MatrixSSOLoginDisplayMixin,
):
    def __init__(
        self,
        client,
        homeserver: str,
        redirect_uri: str | None = None,
    ):
        self.client = client
        self.homeserver = homeserver.rstrip("/")
        self.redirect_uri = redirect_uri
        self.callback_server: SSOCallbackServer | None = None

    async def login(
        self,
        device_name: str,
        device_id: str | None = None,
        show_qr: bool = False,
        url_callback: callable = None,
        *,
        action: str = "login",
    ) -> dict:
        """Run the legacy SSO flow with Matrix v1.18 OAuth-aware context.

        MSC3824 stabilised the optional ``action`` query parameter. This adapter
        is a login client, so ``login`` is the default; ``register`` remains
        available to callers that deliberately reuse the helper for signup.
        """
        if action not in {"login", "register"}:
            raise ValueError("SSO action must be 'login' or 'register'")
        try:
            flows_response = await self.client.get_login_flows()
            self._discover_sso_login_flow(flows_response)

            state = secrets.token_urlsafe(24)
            if not self.redirect_uri:
                raise RuntimeError(
                    "Matrix SSO requires AstrBot unified webhook redirect_uri"
                )

            redirect_uri_with_state = await self._prepare_sso_callback(state)

            params = {
                "redirectUrl": redirect_uri_with_state,
                "action": action,
            }
            sso_url = (
                f"{self.homeserver}/_matrix/client/v3/login/sso/redirect?"
                f"{urlencode(params)}"
            )

            self._announce_sso_login(sso_url, url_callback, show_qr)

            login_token = await self.callback_server.wait_for_callback()

            response = await self.client.login_token(
                token=login_token,
                device_name=device_name,
                device_id=device_id,
            )
            return response
        finally:
            if self.callback_server:
                await self.callback_server.stop()
                self.callback_server = None


__all__ = [
    "MatrixSSOLoginDisplayMixin",
    "MatrixSSOLoginFlowsMixin",
    "MatrixSSOLoginMixin",
    "MatrixSSOLoginServerMixin",
]
