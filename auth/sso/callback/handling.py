"""Handle Matrix SSO callback requests."""

from ...oauth2.core import (
    _get_query_param,
    _get_request_query_params,
    _has_query_param,
    _log,
)


class SSOCallbackHandlingMixin:
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
