"""SSO callback server setup."""

from ...callback import SSOCallbackServer
from ..state import _attach_state_param


class MatrixSSOLoginServerMixin:
    """Prepare the SSO callback server and redirect URI."""

    async def _prepare_sso_callback(self, state: str) -> str:
        """Start the callback server and return the state-tagged redirect URI."""
        self.callback_server = SSOCallbackServer(self.redirect_uri)
        self.callback_server.prepare_callback(expected_state=state)
        redirect_uri = await self.callback_server.start()
        redirect_uri_with_state = _attach_state_param(redirect_uri, state)
        return redirect_uri_with_state


__all__ = ["MatrixSSOLoginServerMixin"]
