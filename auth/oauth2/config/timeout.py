"""OAuth2 HTTP timeout policy."""


class MatrixOAuth2ConfigTimeoutMixin:
    def _resolve_oauth_http_timeout_seconds(
        self, *, cap_seconds: float | None = None
    ) -> float:
        timeout_seconds = self._OAUTH2_HTTP_TIMEOUT_DEFAULT_SECONDS
        get_timeout = getattr(self.client, "get_http_timeout_seconds", None)
        if callable(get_timeout):
            try:
                timeout_seconds = float(get_timeout())
            except Exception:
                timeout_seconds = self._OAUTH2_HTTP_TIMEOUT_DEFAULT_SECONDS

        if timeout_seconds < self._OAUTH2_HTTP_TIMEOUT_MIN_SECONDS:
            timeout_seconds = self._OAUTH2_HTTP_TIMEOUT_MIN_SECONDS

        hard_cap = self._OAUTH2_HTTP_TIMEOUT_MAX_SECONDS
        if cap_seconds is not None:
            try:
                hard_cap = min(
                    hard_cap,
                    max(self._OAUTH2_HTTP_TIMEOUT_MIN_SECONDS, float(cap_seconds)),
                )
            except Exception:
                hard_cap = self._OAUTH2_HTTP_TIMEOUT_MAX_SECONDS

        return min(timeout_seconds, hard_cap)
