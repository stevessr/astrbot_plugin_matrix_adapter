"""Rate-limit backoff and retry for Matrix requests."""

import asyncio
from typing import Any


class MatrixHTTPTransportRetryMixin:
    """Compute retry delays and re-issue requests with backoff."""

    async def _retry_after_seconds(
        self,
        response,
        response_data,
    ) -> float:
        """Return the retry delay in seconds for a rate-limited response."""
        retry_after_ms = response_data.get("retry_after_ms", None)
        if retry_after_ms is None:
            # RFC 7231 Retry-After header
            retry_after_header = response.headers.get("Retry-After")
            if retry_after_header:
                try:
                    retry_after_ms = int(retry_after_header) * 1000
                except (ValueError, TypeError):
                    retry_after_ms = 5000
            else:
                retry_after_ms = 5000
        return retry_after_ms / 1000

    async def _retry_request(
        self,
        method: str,
        endpoint: str,
        data: dict | None,
        params: dict | None,
        authenticated: bool,
        _retry_count: int,
        retry_after_s: float,
    ) -> dict[str, Any]:
        """Sleep and re-issue the request after a transient failure."""
        await asyncio.sleep(retry_after_s)
        return await self._request(
            method,
            endpoint,
            data=data,
            params=params,
            authenticated=authenticated,
            _retry_count=_retry_count + 1,
        )
