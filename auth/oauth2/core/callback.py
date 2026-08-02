"""Unified OAuth2 callback server lifecycle."""

import asyncio

from .logging import _log
from .query import _get_query_param, _get_request_query_params, _has_query_param


class OAuth2CallbackServer:
    """Unified webhook callback controller for OAuth2 flows."""

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
                _log("warning", "OAuth2 callback received before flow was armed")
                return "OAuth2 flow is not ready, please retry.", 503

            query_params = _get_request_query_params(request)

            state = _get_query_param(query_params, "state")
            if state != self.expected_state:
                _log("error", "State mismatch in OAuth2 callback")
                if self.callback_future and not self.callback_future.done():
                    self.callback_future.set_exception(
                        Exception("State mismatch in OAuth2 callback")
                    )
                return "State mismatch", 400

            if _has_query_param(query_params, "error"):
                error = _get_query_param(query_params, "error")
                error_description = _get_query_param(query_params, "error_description")
                _log("error", f"OAuth2 error: {error} - {error_description}")

                if self.callback_future and not self.callback_future.done():
                    self.callback_future.set_exception(
                        Exception(f"OAuth2 error: {error} - {error_description}")
                    )

                return f"Authentication failed: {error}\n{error_description}", 400

            code = _get_query_param(query_params, "code")
            if not code:
                _log("error", "No authorization code in OAuth2 callback")
                if self.callback_future and not self.callback_future.done():
                    self.callback_future.set_exception(
                        Exception("No authorization code received")
                    )
                return "No authorization code", 400

            if self.callback_future and not self.callback_future.done():
                self.callback_future.set_result(code)

            return "Authentication successful! You can close this window.", 200

        except Exception as e:
            _log("error", f"Error handling OAuth2 callback: {e}")
            if self.callback_future and not self.callback_future.done():
                self.callback_future.set_exception(e)
            return f"Error: {str(e)}", 500

    async def start(self) -> str:
        _log(
            "info",
            f"OAuth2 callback will use AstrBot unified webhook: {self.redirect_uri}",
        )
        return self.redirect_uri

    async def stop(self):
        try:
            if self.callback_future and not self.callback_future.done():
                self.callback_future.cancel()
            self.callback_future = None
            self.expected_state = None
            self._flow_armed = False
            _log("info", "OAuth2 callback handler stopped")
        except Exception as e:
            _log("error", f"Error stopping OAuth2 callback handler: {e}")

    def prepare_callback(self, expected_state: str) -> None:
        if not expected_state:
            raise ValueError("expected_state is required")
        loop = asyncio.get_running_loop()
        self.expected_state = expected_state
        self.callback_future = loop.create_future()
        self._flow_armed = True

    async def wait_for_callback(self, timeout: int = 300) -> str:
        if self.callback_future is None:
            raise RuntimeError("OAuth2 callback flow not prepared")

        try:
            code = await asyncio.wait_for(self.callback_future, timeout=timeout)
            return code
        except asyncio.TimeoutError:
            _log("error", "OAuth2 callback timeout")
            raise
        finally:
            self.callback_future = None
            self.expected_state = None
            self._flow_armed = False
