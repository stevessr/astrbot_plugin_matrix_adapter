"""Matrix SSO login flow."""

import secrets
from urllib.parse import urlencode

from ....constants import LOGIN_TYPE_SSO
from ...oauth2.core import _log
from ..callback import SSOCallbackServer
from ..qr import _build_terminal_qr
from .state import _attach_state_param


class MatrixSSOLoginMixin:
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
    ) -> dict:
        try:
            flows_response = await self.client.get_login_flows()
            flows = flows_response.get("flows", [])

            sso_flow = None
            for flow in flows:
                if flow.get("type") == LOGIN_TYPE_SSO:
                    sso_flow = flow
                    break

            if not sso_flow:
                raise RuntimeError("SSO login not supported by this homeserver.")

            idps = sso_flow.get("identity_providers", []) or []
            if idps:
                idp_names = ", ".join(
                    [f"{i.get('name', i.get('id', 'unknown'))}" for i in idps]
                )
                _log("info", f"SSO identity providers: {idp_names}")

            state = secrets.token_urlsafe(24)
            if not self.redirect_uri:
                raise RuntimeError(
                    "Matrix SSO requires AstrBot unified webhook redirect_uri"
                )

            self.callback_server = SSOCallbackServer(self.redirect_uri)
            self.callback_server.prepare_callback(expected_state=state)
            redirect_uri = await self.callback_server.start()
            redirect_uri_with_state = _attach_state_param(redirect_uri, state)

            params = {"redirectUrl": redirect_uri_with_state}
            sso_url = (
                f"{self.homeserver}/_matrix/client/v3/login/sso/redirect?"
                f"{urlencode(params)}"
            )

            if url_callback:
                url_callback(sso_url)

            _log("info", "=" * 60)
            _log("info", "SSO Authentication Required")
            _log("info", "=" * 60)
            _log("info", f"Please open this URL in your browser:\n\n{sso_url}\n")
            if show_qr:
                terminal_qr = _build_terminal_qr(sso_url)
                if terminal_qr:
                    _log("info", "Scan this QR code to continue authentication:")
                    _log("info", f"\n{terminal_qr}")
                else:
                    _log(
                        "warning",
                        "QR rendering dependency missing. Install 'qrcode' to display terminal QR codes.",
                    )
            _log("info", "Waiting for SSO callback...")
            _log("info", "=" * 60)

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
