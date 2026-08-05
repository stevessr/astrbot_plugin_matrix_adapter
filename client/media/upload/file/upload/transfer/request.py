"""Matrix media upload single-request POST."""

from typing import Any


class MediaUploadTransferRequestMixin:
    """POST one upload attempt and parse the response."""

    async def _post_upload_request_once(
        self,
        url: str,
        headers: dict[str, str],
        params: dict[str, str],
        hashing_reader,
    ) -> tuple:
        async with self.session.post(
            url,
            data=hashing_reader,
            headers=headers,
            params=params,
        ) as response:
            response_data: dict[str, Any] = {}
            try:
                parsed = await response.json(content_type=None)
                if isinstance(parsed, dict):
                    response_data = parsed
            except Exception:
                try:
                    response_data = {"error": await response.text()}
                except Exception:
                    response_data = {}
            return response.status, response_data, response.headers
