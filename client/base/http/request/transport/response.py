"""Response parsing and error normalization."""

from typing import Any

from ......constants import ERROR_TRUNCATE_LENGTH_200
from ....errors import MatrixAPIError


class MatrixHTTPTransportResponseMixin:
    """Normalize Matrix API responses into JSON or structured errors."""

    async def _raise_response_error(self, response) -> None:
        """Raise a structured MatrixAPIError for an error status response."""
        # 尝试获取错误信息，但处理非 JSON 响应
        try:
            response_data = await response.json()
            error_code = response_data.get("errcode", "UNKNOWN")
            error_msg = response_data.get("error", "Unknown error")
            error_detail = f"Matrix API error: {error_code} - {error_msg} (status: {response.status})"
            # Raise structured error
            raise MatrixAPIError(response.status, response_data, error_detail)
        except MatrixAPIError:
            raise
        except Exception:
            # 如果不是 JSON 响应，获取文本内容
            content_type = response.headers.get("content-type", "").lower()
            if "text/html" in content_type:
                error_detail = f"Matrix API error: HTML error page returned (status: {response.status})"
                raise MatrixAPIError(response.status, "HTML error page", error_detail)
            else:
                text = await response.text()
                error_detail = f"Matrix API error: Non-JSON response (status: {response.status}): {text[:ERROR_TRUNCATE_LENGTH_200]}"
                raise MatrixAPIError(response.status, text, error_detail)

    async def _parse_response_json(self, response) -> dict[str, Any]:
        """Parse a successful response body as JSON."""
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
