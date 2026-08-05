"""Single-attempt POST + response parsing for byte-buffer uploads."""


class MediaUploadBytesRequestMixin:
    """Perform one HTTP POST and parse the JSON/text response."""

    async def _post_media_upload_once(
        self,
        *,
        url: str,
        data: bytes,
        headers: dict,
        params: dict,
    ) -> tuple[int, dict, object]:
        async with self.session.post(
            url, data=data, headers=headers, params=params
        ) as response:
            response_data: dict = {}
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
