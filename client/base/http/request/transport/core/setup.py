"""Matrix HTTP request setup."""


class MatrixHTTPTransportSetupMixin:
    """Build the URL, headers, and timeout for one request."""

    def _prepare_http_request(
        self,
        method: str,
        endpoint: str,
        data: dict | None,
        params: dict | None,
        authenticated: bool,
        timeout_override: int | None,
    ) -> tuple:
        timeout = self._build_http_timeout(timeout_override)

        url = f"{self.homeserver}{endpoint}"
        headers = (
            self._get_headers()
            if authenticated
            else {
                "Content-Type": "application/json",
                "User-Agent": "AstrBot Matrix Client/1.0",
            }
        )
        return url, headers, timeout
