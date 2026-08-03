"""Authenticated Matrix HTTP header helpers."""


class MatrixHTTPHeadersMixin:
    """Build headers for Matrix API requests."""

    def _get_headers(self) -> dict[str, str]:
        """Get HTTP headers for authenticated requests"""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "AstrBot Matrix Client/1.0",
        }
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        return headers
