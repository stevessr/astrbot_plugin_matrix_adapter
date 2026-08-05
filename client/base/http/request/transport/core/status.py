"""Matrix HTTP response status handling."""

from typing import Any

from astrbot.api import logger

from .......constants import HTTP_ERROR_STATUS_400


class MatrixHTTPTransportStatusMixin:
    """Route a response through rate-limit, retry, and error handling."""

    async def _handle_http_status(
        self,
        response,
        method: str,
        endpoint: str,
        data: dict | None,
        params: dict | None,
        authenticated: bool,
        _retry_count: int,
        max_retries: int,
    ) -> dict[str, Any]:
        # 处理 429 速率限制
        # 参考：https://spec.matrix.org/latest/client-server-api/#rate-limiting
        if response.status == 429 and _retry_count < max_retries:
            try:
                response_data = await response.json()
                retry_after_s = await self._retry_after_seconds(response, response_data)
                logger.warning(
                    f"速率限制，等待 {retry_after_s:.1f} 秒后重试 "
                    f"(retry {_retry_count + 1}/{max_retries})"
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
        if response.status >= 500 and _retry_count < max_retries:
            retry_after_s = 5 * (_retry_count + 1)
            logger.warning(
                f"服务器错误 {response.status}，等待 {retry_after_s:.1f} 秒后重试 "
                f"(retry {_retry_count + 1}/{max_retries})"
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
