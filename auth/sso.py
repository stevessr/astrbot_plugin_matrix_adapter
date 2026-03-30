"""
Matrix SSO Authentication Module
Implements m.login.sso flow with AstrBot unified webhook callbacks
"""

import asyncio
import io
import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .oauth2_core import _get_request_query_params, _log


def _build_terminal_qr(data: str) -> str | None:
    """Build an ASCII QR code for terminal display.

    Returns None when qrcode dependency is unavailable.
    """
    try:
        import qrcode
    except Exception:
        return None

    qr = qrcode.QRCode(border=1)
    qr.add_data(data)
    qr.make(fit=True)

    output = io.StringIO()
    qr.print_ascii(out=output, invert=True)
    return output.getvalue()


class SSOCallbackServer:
    """Unified webhook callback controller for Matrix SSO callbacks."""

    def __init__(self, redirect_uri: str):
        if not redirect_uri:
            raise ValueError("redirect_uri is required")
        self.redirect_uri = redirect_uri
        self.callback_future: asyncio.Future | None = None
        self.expected_state: str | None = None
        self._flow_armed = False

    async def handle_callback(self, request):
        try:
            if (
                not self._flow_armed
                or self.callback_future is None
                or self.expected_state is None
            ):
                _log("warning", "SSO callback received before flow was armed")
                return "SSO flow is not ready, please retry.", 503

            query_params = _get_request_query_params(request)
            if self.expected_state:
                state = query_params.get("state")
                if state != self.expected_state:
                    _log("error", "SSO callback state mismatch")
                    if self.callback_future and not self.callback_future.done():
                        self.callback_future.set_exception(
                            Exception("SSO callback state mismatch")
                        )
                    return "State mismatch", 400

            if "error" in query_params:
                error = query_params.get("error")
                error_description = query_params.get("error_description", "")
                _log("error", f"SSO error: {error} - {error_description}")
                if self.callback_future and not self.callback_future.done():
                    self.callback_future.set_exception(
                        Exception(f"SSO error: {error} - {error_description}")
                    )
                return f"Authentication failed: {error}\n{error_description}", 400

            login_token = query_params.get("loginToken") or query_params.get(
                "login_token"
            )
            if not login_token:
                _log("error", "No loginToken in SSO callback")
                if self.callback_future and not self.callback_future.done():
                    self.callback_future.set_exception(
                        Exception("No loginToken received")
                    )
                return "No loginToken in callback", 400

            if self.callback_future and not self.callback_future.done():
                self.callback_future.set_result(login_token)

            return "Authentication successful! You can close this window.", 200

        except Exception as e:
            _log("error", f"Error handling SSO callback: {e}")
            if self.callback_future and not self.callback_future.done():
                self.callback_future.set_exception(e)
            return f"Error: {str(e)}", 500

    async def start(self) -> str:
        _log(
            "info",
            f"SSO callback will use AstrBot unified webhook: {self.redirect_uri}",
        )
        return self.redirect_uri

    async def stop(self):
        if self.callback_future and not self.callback_future.done():
            self.callback_future.cancel()
        self.callback_future = None
        self.expected_state = None
        self._flow_armed = False
        _log("info", "SSO callback handler stopped")

    def prepare_callback(self, expected_state: str) -> None:
        if not expected_state:
            raise ValueError("expected_state is required")
        loop = asyncio.get_running_loop()
        self.expected_state = expected_state
        self.callback_future = loop.create_future()
        self._flow_armed = True

    async def wait_for_callback(self, timeout: int = 300) -> str:
        if self.callback_future is None:
            raise RuntimeError("SSO callback flow not prepared")
        try:
            token = await asyncio.wait_for(self.callback_future, timeout=timeout)
            return token
        finally:
            self.callback_future = None
            self.expected_state = None
            self._flow_armed = False


def _attach_state_param(url: str, state: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["state"] = state
    return urlunparse(parsed._replace(query=urlencode(query)))


class MatrixSSO:
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
                if flow.get("type") == "m.login.sso":
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

    async def handle_webhook_callback(self, request):
        if not self.callback_server:
            return "SSO flow is not ready, please retry.", 503
        return await self.callback_server.handle_callback(request)
