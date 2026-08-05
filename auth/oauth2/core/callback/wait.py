"""OAuth2 callback result waiting."""

import asyncio

from ..logging import _log


class _OAuth2CallbackWaitMixin:
    """Await the authorization code from the callback server."""

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


__all__ = ["_OAuth2CallbackWaitMixin"]
