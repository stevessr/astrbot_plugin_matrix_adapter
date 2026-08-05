"""OAuth2 callback server state and lifecycle."""

import asyncio

from ..logging import _log


class _OAuth2CallbackStateMixin:
    """Armed state and lifecycle for the callback server."""

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


__all__ = ["_OAuth2CallbackStateMixin"]
