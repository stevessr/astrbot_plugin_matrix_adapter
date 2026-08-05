"""OAuth2 callback request handling."""

from ..logging import _log
from ..query import _get_query_param, _get_request_query_params, _has_query_param


class _OAuth2CallbackHandlerMixin:
    """Handle a single webhook callback request."""

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


__all__ = ["_OAuth2CallbackHandlerMixin"]
