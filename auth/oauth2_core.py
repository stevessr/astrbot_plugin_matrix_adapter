"""
OAuth2 core helpers: logging and callback server.
"""

import asyncio

from aiohttp import web

from astrbot.api import logger


def _log(level: str, msg: str):
    """Log messages with AstrBot extra fields."""
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
    """HTTP server for handling OAuth2 callbacks."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8765):
        self.host = host
        self.port = port
        self.app = web.Application()
        self.runner: web.AppRunner | None = None
        self.site: web.TCPSite | None = None
        self.callback_future: asyncio.Future | None = None
        self.state: str | None = None

        self.app.router.add_get("/callback", self._handle_callback)
        self.app.router.add_get("/", self._handle_root)

    async def _handle_root(self, request: web.Request) -> web.Response:
        return web.Response(
            text="Matrix OAuth2 Authentication Server\nWaiting for OAuth2 callback...",
            content_type="text/plain",
        )

    async def _handle_callback(self, request: web.Request) -> web.Response:
        try:
            query_params = request.query

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

            state = query_params.get("state")
            if state != self.state:
                _log("error", "State mismatch in OAuth2 callback")
                if self.callback_future and not self.callback_future.done():
                    self.callback_future.set_exception(
                        Exception("State mismatch in OAuth2 callback")
                    )
                return web.Response(text="State mismatch", status=400)

            code = query_params.get("code")
            if not code:
                _log("error", "No authorization code in OAuth2 callback")
                if self.callback_future and not self.callback_future.done():
                    self.callback_future.set_exception(
                        Exception("No authorization code received")
                    )
                return web.Response(text="No authorization code", status=400)

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
        try:
            if self.site:
                await self.site.stop()
            if self.runner:
                await self.runner.cleanup()
            _log("info", "OAuth2 callback server stopped")
        except Exception as e:
            _log("error", f"Error stopping OAuth2 callback server: {e}")

    async def wait_for_callback(self, state: str, timeout: int = 300) -> str:
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
