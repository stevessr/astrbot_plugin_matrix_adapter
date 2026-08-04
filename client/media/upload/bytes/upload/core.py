"""Byte-buffer Matrix media upload entry orchestration."""

import asyncio
from typing import Any

from astrbot.api import logger


class MediaUploadBytesCoreMixin:
    """Upload in-memory media: entry orchestration (session, cache, dedup)."""

    async def upload_file(
        self, data: bytes, content_type: str, filename: str
    ) -> dict[str, Any]:
        """
        Upload a file to the Matrix media repository

        Args:
            data: File data as bytes
            content_type: MIME type
            filename: Filename

        Returns:
            Upload response with content_uri
        """
        await self._ensure_session()
        self._ensure_media_upload_cache()

        safe_content_type = self._validate_media_upload_security(
            filename=filename,
            declared_content_type=content_type,
            file_head=data[: self._MEDIA_UPLOAD_SNIFF_BYTES],
        )

        cache_key = self._build_media_upload_cache_key(data, safe_content_type)
        cached_response = self._get_cached_upload_result(cache_key)
        if cached_response:
            return cached_response

        existing_task = self._media_upload_inflight.get(cache_key)
        if existing_task:
            logger.debug("Joining in-flight Matrix media upload task")
            return await existing_task

        async def _perform_upload() -> dict[str, Any]:
            return await self._perform_media_upload(
                cache_key=cache_key,
                safe_content_type=safe_content_type,
                filename=filename,
                data=data,
            )

        upload_task = asyncio.create_task(_perform_upload())
        self._media_upload_inflight[cache_key] = upload_task
        try:
            return await upload_task
        finally:
            current_task = self._media_upload_inflight.get(cache_key)
            if current_task is upload_task:
                self._media_upload_inflight.pop(cache_key, None)
