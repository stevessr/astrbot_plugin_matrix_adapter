"""File-backed Matrix media upload preparation and caching."""

import asyncio
from pathlib import Path
from typing import Any

from astrbot.api import logger


class MediaUploadPrimaryMixin:
    """Validate, cache, and coordinate file uploads."""

    async def upload_file_path(
        self, file_path: str | Path, content_type: str, filename: str | None = None
    ) -> dict[str, Any]:
        """
        Upload a local file to the Matrix media repository without loading it fully
        into memory.
        """
        await self._ensure_session()
        self._ensure_media_upload_cache()

        path = Path(file_path)
        if not await asyncio.to_thread(path.is_file):
            raise FileNotFoundError(
                f"Matrix media upload source file not found: {path}"
            )

        upload_filename = filename or path.name
        file_head = await asyncio.to_thread(
            self._read_file_head, path, self._MEDIA_UPLOAD_SNIFF_BYTES
        )
        safe_content_type = self._validate_media_upload_security(
            filename=upload_filename,
            declared_content_type=content_type,
            file_head=file_head,
        )

        path_cache_key = await asyncio.to_thread(
            self._build_media_upload_cache_key_from_file_state,
            path,
            safe_content_type,
        )
        cached_response = self._get_cached_upload_result(path_cache_key)
        if cached_response:
            return cached_response

        existing_task = self._media_upload_inflight.get(path_cache_key)
        if existing_task:
            logger.debug("Joining in-flight Matrix media upload task")
            return await existing_task

        upload_task = asyncio.create_task(
            self._perform_upload_from_path(
                path=path,
                safe_content_type=safe_content_type,
                upload_filename=upload_filename,
                path_cache_key=path_cache_key,
            )
        )

        self._media_upload_inflight[path_cache_key] = upload_task
        try:
            return await upload_task
        finally:
            current_task = self._media_upload_inflight.get(path_cache_key)
            if current_task is upload_task:
                self._media_upload_inflight.pop(path_cache_key, None)
