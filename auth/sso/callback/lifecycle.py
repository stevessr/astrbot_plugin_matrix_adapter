"""SSO callback server lifecycle operations."""

import asyncio

from ...oauth2.core import _log


class SSOCallbackLifecycleMixin:
    def __init__(self, redirect_uri: str):
        if not redirect_uri:
            raise ValueError("redirect_uri is required")
        self.redirect_uri = redirect_uri
        self.callback_future: asyncio.Future | None = None
        self.expected_state: str | None = None
        self._flow_armed = False

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
