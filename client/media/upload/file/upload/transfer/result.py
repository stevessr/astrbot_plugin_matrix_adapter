"""Matrix media upload response consumption."""

from typing import Any


class MediaUploadTransferResultMixin:
    """Consume a successful upload response into a cached result."""

    async def _consume_upload_result(
        self,
        response_data: dict[str, Any],
        hashing_reader,
        path_cache_key: str,
        safe_content_type: str,
    ) -> dict[str, Any]:
        content_uri = response_data.get("content_uri")
        upload_id = response_data.get("upload_id")
        if isinstance(content_uri, str) and content_uri:
            # Synchronous upload
            digest_cache_key = self._build_media_upload_cache_key_from_digest(
                hashing_reader.hexdigest(),
                safe_content_type,
            )
            self._save_upload_cache_result(path_cache_key, content_uri)
            self._save_upload_cache_result(digest_cache_key, content_uri)
            return response_data
        elif isinstance(upload_id, str) and upload_id:
            # Async upload (MSC2246) — poll until done
            poll_response = await self._poll_upload_status(upload_id)
            poll_uri = poll_response.get("content_uri", "")
            if isinstance(poll_uri, str) and poll_uri:
                self._save_upload_cache_result(path_cache_key, poll_uri)
                self._save_upload_cache_result(
                    self._build_media_upload_cache_key_from_digest(
                        hashing_reader.hexdigest(),
                        safe_content_type,
                    ),
                    poll_uri,
                )
                return poll_response
            raise Exception(
                f"Matrix async upload finished but missing "
                f"content_uri (upload_id={upload_id})"
            )
        raise Exception(
            "Matrix media upload error: missing content_uri or upload_id in response"
        )
