"""
Matrix SSO Authentication Module
Implements m.login.sso flow with local callback server
"""

import asyncio
from urllib.parse import urlencode

from aiohttp import web

from .oauth2_core import _log


class SSOCallbackServer:
    """HTTP server for handling Matrix SSO callbacks."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8765):
        self.host = host
        self.port = port
        self.app = web.Application()
        self.runner: web.AppRunner | None = None
        self.site: web.TCPSite | None = None
        self.callback_future: asyncio.Future | None = None

        self.app.router.add_get("/callback", self._handle_callback)
        self.app.router.add_get("/", self._handle_root)

    async def _handle_root(self, request: web.Request) -> web.Response:
        return web.Response(
            text="Matrix SSO Authentication Server\nWaiting for callback...",
            content_type="text/plain",
        )

    async def _handle_callback(self, request: web.Request) -> web.Response:
        try:
            query_params = request.query
            if "error" in query_params:
                error = query_params.get("error")
                error_description = query_params.get("error_description", "")
                _log("error", f"SSO error: {error} - {error_description}")
                if self.callback_future and not self.callback_future.done():
                    self.callback_future.set_exception(
                        Exception(f"SSO error: {error} - {error_description}")
                    )
                return web.Response(
                    text=f"Authentication failed: {error}\n{error_description}",
                    status=400,
                )

            login_token = query_params.get("loginToken") or query_params.get(
                "login_token"
            )
            if not login_token:
                _log("error", "No loginToken in SSO callback")
                if self.callback_future and not self.callback_future.done():
                    self.callback_future.set_exception(
                        Exception("No loginToken received")
                    )
                return web.Response(text="No loginToken in callback", status=400)

            if self.callback_future and not self.callback_future.done():
                self.callback_future.set_result(login_token)

            return web.Response(
                text="Authentication successful! You can close this window.",
                content_type="text/plain",
            )

        except Exception as e:
            _log("error", f"Error handling SSO callback: {e}")
            if self.callback_future and not self.callback_future.done():
                self.callback_future.set_exception(e)
            return web.Response(text=f"Error: {str(e)}", status=500)

    async def start(self) -> str:
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()
        callback_url = f"http://{self.host}:{self.port}/callback"
        _log("info", f"SSO callback server started at {callback_url}")
        return callback_url

    async def stop(self):
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()
        _log("info", "SSO callback server stopped")

    async def wait_for_callback(self, timeout: int = 300) -> str:
        self.callback_future = asyncio.Future()
        try:
            token = await asyncio.wait_for(self.callback_future, timeout=timeout)
            return token
        finally:
            self.callback_future = None


class MatrixSSO:
    def __init__(
        self,
        client,
        homeserver: str,
        callback_port: int = 8765,
        callback_host: str = "127.0.0.1",
    ):
        self.client = client
        self.homeserver = homeserver.rstrip("/")
        self.callback_port = callback_port
        self.callback_host = callback_host
        self.callback_server: SSOCallbackServer | None = None

    async def login(self, device_name: str, device_id: str | None = None) -> dict:
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

            self.callback_server = SSOCallbackServer(
                host=self.callback_host, port=self.callback_port
            )
            redirect_uri = await self.callback_server.start()

            params = {"redirectUrl": redirect_uri}
            sso_url = (
                f"{self.homeserver}/_matrix/client/v3/login/sso/redirect?"
                f"{urlencode(params)}"
            )

            _log("info", "=" * 60)
            _log("info", "SSO Authentication Required")
            _log("info", "=" * 60)
            _log("info", f"Please open this URL in your browser:\\n\\n{sso_url}\\n")
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
