"""Matrix SSO login flow."""

import secrets
from urllib.parse import quote, urlencode

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
        idp_id: str | None = None,
    ) -> dict:
        """Run Matrix SSO with optional stable identity-provider selection.

        ``idp_id`` selects the v1.1 / MSC2858
        ``/login/sso/redirect/{idpId}`` endpoint. If the homeserver advertises
        ``identity_providers`` in the SSO login flow, an unknown ID is rejected
        locally instead of sending the user to a guaranteed error page.
        """
        if action not in {"login", "register"}:
            raise ValueError("SSO action must be 'login' or 'register'")
        if idp_id is not None and (
            not isinstance(idp_id, str) or not idp_id.strip()
        ):
            raise ValueError("idp_id must be a non-empty string when provided")

        try:
            flows_response = await self.client.get_login_flows()
            sso_flow = self._discover_sso_login_flow(flows_response)

            if idp_id is not None:
                idps = sso_flow.get("identity_providers", [])
                if isinstance(idps, list) and idps:
                    advertised = {
                        provider.get("id")
                        for provider in idps
                        if isinstance(provider, dict)
                        and isinstance(provider.get("id"), str)
                    }
                    if idp_id not in advertised:
                        raise ValueError(
                            f"SSO identity provider is not advertised: {idp_id}"
                        )

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
            if idp_id is None:
                redirect_path = "/_matrix/client/v3/login/sso/redirect"
            else:
                redirect_path = (
                    "/_matrix/client/v3/login/sso/redirect/"
                    + quote(idp_id, safe="")
                )
            sso_url = f"{self.homeserver}{redirect_path}?{urlencode(params)}"

            self._announce_sso_login(sso_url, url_callback, show_qr)
            login_token = await self.callback_server.wait_for_callback()

            return await self.client.login_token(
                token=login_token,
                device_name=device_name,
                device_id=device_id,
            )
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
