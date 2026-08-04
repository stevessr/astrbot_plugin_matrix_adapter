"""Matrix HTTP request and response handling."""

from typing import Any

import aiohttp

from astrbot.api import logger

from ......constants import HTTP_ERROR_STATUS_400


class MatrixHTTPTransportCoreMixin:
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

        try:
            async with self.session.request(
                method,
                url,
                json=data,
                params=params,
                headers=headers,
                timeout=timeout,
            ) as response:
                # 处理 429 速率限制
                # 参考：https://spec.matrix.org/latest/client-server-api/#rate-limiting
                if response.status == 429 and _retry_count < MAX_RETRIES:
                    try:
                        response_data = await response.json()
                        retry_after_s = await self._retry_after_seconds(
                            response, response_data
                        )
                        logger.warning(
                            f"速率限制，等待 {retry_after_s:.1f} 秒后重试 "
                            f"(retry {_retry_count + 1}/{MAX_RETRIES})"
                        )
                        return await self._retry_request(
                            method,
                            endpoint,
                            data,
                            params,
                            authenticated,
                            _retry_count,
                            retry_after_s,
                        )
                    except Exception:
                        pass  # 继续正常错误处理

                # 重试服务器错误 (5xx) 和瞬态错误
                if response.status >= 500 and _retry_count < MAX_RETRIES:
                    retry_after_s = 5 * (_retry_count + 1)
                    logger.warning(
                        f"服务器错误 {response.status}，等待 {retry_after_s:.1f} 秒后重试 "
                        f"(retry {_retry_count + 1}/{MAX_RETRIES})"
                    )
                    return await self._retry_request(
                        method,
                        endpoint,
                        data,
                        params,
                        authenticated,
                        _retry_count,
                        retry_after_s,
                    )

                # 检查响应状态
                if response.status >= HTTP_ERROR_STATUS_400:
                    await self._raise_response_error(response)

                # 对于成功响应，尝试解析 JSON
                return await self._parse_response_json(response)

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
