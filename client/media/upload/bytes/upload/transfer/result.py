"""Success-path consumption of an upload response."""


class MediaUploadBytesResultMixin:
    """Extract the upload result, polling async uploads when needed."""

    async def _consume_upload_result(
        self, *, response_data: dict, cache_key: str
    ) -> dict:
        content_uri = response_data.get("content_uri")
        upload_id = response_data.get("upload_id")
        if isinstance(content_uri, str) and content_uri:
            # Synchronous upload — content_uri available immediately
            self._save_upload_cache_result(cache_key, content_uri)
            return response_data
        elif isinstance(upload_id, str) and upload_id:
            # Async upload (MSC2246) — poll until done
            poll_response = await self._poll_upload_status(upload_id)
            poll_uri = poll_response.get("content_uri", "")
            if isinstance(poll_uri, str) and poll_uri:
                self._save_upload_cache_result(cache_key, poll_uri)
                return poll_response
            raise Exception(
                f"Matrix async upload finished but missing "
                f"content_uri (upload_id={upload_id})"
            )
        else:
            raise Exception(
                "Matrix media upload error: "
                "missing content_uri or upload_id in response"
            )
