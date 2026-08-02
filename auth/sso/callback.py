"""Unified webhook callback controller for Matrix SSO."""

import asyncio

from ..oauth2.core import (
    _get_query_param,
    _get_request_query_params,
    _has_query_param,
    _log,
)


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
                state = _get_query_param(query_params, "state")
                if state != self.expected_state:
                    _log("error", "SSO callback state mismatch")
                    if self.callback_future and not self.callback_future.done():
                        self.callback_future.set_exception(
                            Exception("SSO callback state mismatch")
                        )
                    return "State mismatch", 400

            if _has_query_param(query_params, "error"):
                error = _get_query_param(query_params, "error")
                error_description = _get_query_param(query_params, "error_description")
                _log("error", f"SSO error: {error} - {error_description}")
                if self.callback_future and not self.callback_future.done():
                    self.callback_future.set_exception(
                        Exception(f"SSO error: {error} - {error_description}")
                    )
                return f"Authentication failed: {error}\n{error_description}", 400

            login_token = _get_query_param(
                query_params, "loginToken"
            ) or _get_query_param(query_params, "login_token")
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
