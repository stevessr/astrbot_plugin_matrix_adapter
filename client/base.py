"""
Matrix HTTP Client - Base module
Provides core HTTP request functionality
"""

from typing import Any

import aiohttp

from astrbot.api import logger

from ..constants import (
    ERROR_TRUNCATE_LENGTH_200,
    HTTP_ERROR_STATUS_400,
)


class MatrixAPIError(Exception):
    """Matrix API Error"""

    def __init__(self, status: int, data: dict | str, message: str):
        self.status = status
        self.data = data
        self.message = message
        super().__init__(message)


class MatrixClientBase:
    """
    Base class for Matrix HTTP client
    Provides core HTTP request functionality
    """

    def __init__(self, homeserver: str):
        """
        Initialize Matrix HTTP client base

        Args:
            homeserver: Matrix homeserver URL (e.g., https://matrix.org)
        """
        self.homeserver = homeserver.rstrip("/")
        self.access_token: str | None = None
        self.user_id: str | None = None
        self.device_id: str | None = None
        self.session: aiohttp.ClientSession | None = None
        self._next_batch: str | None = None

    async def _ensure_session(self):
        """Ensure aiohttp session exists"""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()

    async def close(self):
        """Close the HTTP session"""
        if self.session and not self.session.closed:
            await self.session.close()

    def _get_headers(self) -> dict[str, str]:
        """Get HTTP headers for authenticated requests"""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "AstrBot Matrix Client/1.0",
        }
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        return headers

    async def _request(
        self,
        method: str,
        endpoint: str,
        data: dict | None = None,
        params: dict | None = None,
        authenticated: bool = True,
        _retry_count: int = 0,
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
                method, url, json=data, params=params, headers=headers
            ) as response:
                # 处理 429 速率限制
                # 参考：https://spec.matrix.org/latest/client-server-api/#rate-limiting
                if response.status == 429 and _retry_count < MAX_RETRIES:
                    try:
                        response_data = await response.json()
                        retry_after_ms = response_data.get("retry_after_ms", 5000)
                        retry_after_s = retry_after_ms / 1000
                        logger.warning(
                            f"速率限制，等待 {retry_after_s:.1f} 秒后重试 "
                            f"(retry {_retry_count + 1}/{MAX_RETRIES})"
                        )
                        await asyncio.sleep(retry_after_s)
                        return await self._request(
                            method,
                            endpoint,
                            data=data,
                            params=params,
                            authenticated=authenticated,
                            _retry_count=_retry_count + 1,
                        )
                    except Exception:
                        pass  # 继续正常错误处理

                # 检查响应状态
                if response.status >= HTTP_ERROR_STATUS_400:
                    # 尝试获取错误信息，但处理非 JSON 响应
                    try:
                        response_data = await response.json()
                        error_code = response_data.get("errcode", "UNKNOWN")
                        error_msg = response_data.get("error", "Unknown error")
                        error_detail = f"Matrix API error: {error_code} - {error_msg} (status: {response.status})"
                        # Raise structured error
                        raise MatrixAPIError(
                            response.status, response_data, error_detail
                        )
                    except MatrixAPIError:
                        raise
                    except Exception:
                        # 如果不是 JSON 响应，获取文本内容
                        content_type = response.headers.get("content-type", "").lower()
                        if "text/html" in content_type:
                            error_detail = f"Matrix API error: HTML error page returned (status: {response.status})"
                            raise MatrixAPIError(
                                response.status, "HTML error page", error_detail
                            )
                        else:
                            text = await response.text()
                            error_detail = f"Matrix API error: Non-JSON response (status: {response.status}): {text[:ERROR_TRUNCATE_LENGTH_200]}"
                            raise MatrixAPIError(response.status, text, error_detail)

                # 对于成功响应，尝试解析 JSON
                try:
                    response_data = await response.json()
                except Exception:
                    # 如果不是 JSON 响应，获取文本内容
                    content_type = response.headers.get("content-type", "").lower()
                    if "text/html" in content_type:
                        raise Exception(
                            f"Matrix API error: HTML response instead of JSON (status: {response.status})"
                        )
                    else:
                        text = await response.text()
                        raise Exception(
                            f"Matrix API error: Non-JSON response (status: {response.status}): {text[:ERROR_TRUNCATE_LENGTH_200]}"
                        )

                return response_data

        except aiohttp.ClientError as e:
            logger.error(f"Matrix HTTP request failed: {e}")
            raise

