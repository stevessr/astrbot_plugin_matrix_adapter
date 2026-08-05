"""Matrix HTTP request and response handling."""

from typing import Any

import aiohttp

from astrbot.api import logger

from .setup import MatrixHTTPTransportSetupMixin
from .status import MatrixHTTPTransportStatusMixin


class MatrixHTTPTransportRequestMixin(
    MatrixHTTPTransportSetupMixin,
    MatrixHTTPTransportStatusMixin,
):
    """Issue Matrix API requests and normalize failures."""

    async def _request(
        self,
        method: str,
        endpoint: str,
        data: dict | None = None,
        params: dict | None = None,
        authenticated: bool = True,
        _retry_count: int = 0,
        timeout_override: int | None = None,
    ) -> dict[str, Any]:
        """
        Make HTTP request to Matrix server

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (e.g., /_matrix/client/v3/login)
            data: JSON data for request body
            params: URL query parameters
            authenticated: Whether to include access token
            _retry_count: Internal retry counter for rate limiting

        Returns:
            Response JSON data

        Raises:
            Exception: On HTTP errors
        """
        import asyncio

        MAX_RETRIES = 3
        await self._ensure_session()

        url, headers, timeout = self._prepare_http_request(
            method,
            endpoint,
            data,
            params,
            authenticated,
            timeout_override,
        )

        try:
            async with self.session.request(
                method,
                url,
                json=data,
                params=params,
                headers=headers,
                timeout=timeout,
            ) as response:
                return await self._handle_http_status(
                    response,
                    method,
                    endpoint,
                    data,
                    params,
                    authenticated,
                    _retry_count,
                    MAX_RETRIES,
                )

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"Matrix HTTP request failed: {e}")
            if _retry_count < MAX_RETRIES:
                retry_after_s = 5 * (_retry_count + 1)
                return await self._retry_request(
                    method,
                    endpoint,
                    data,
                    params,
                    authenticated,
                    _retry_count,
                    retry_after_s,
                )
            raise
