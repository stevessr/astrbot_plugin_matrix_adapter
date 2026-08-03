"""File-backed Matrix media upload operation."""

import asyncio
from pathlib import Path
from typing import Any

import aiohttp

from astrbot.api import logger

from .....constants import HTTP_ERROR_STATUS_400


class MediaUploadFileOperationMixin:
    """Upload local files without buffering the complete file in memory."""

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

        async def _perform_upload_from_path() -> dict[str, Any]:
            headers = {
                "Content-Type": safe_content_type,
                "Authorization": f"Bearer {self.access_token}",
                "User-Agent": "AstrBot Matrix Client/1.0",
            }
            params = {"filename": upload_filename}
            endpoints = self._get_media_upload_endpoints()
            last_error: Exception | None = None

            for endpoint_index, endpoint in enumerate(endpoints):
                url = f"{self.homeserver}{endpoint}"
                attempt = 0

                while True:
                    file_handle = None
                    try:
                        file_handle = await asyncio.to_thread(path.open, "rb")
                        hashing_reader = self._HashingFileReader(file_handle)
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

                            if response.status >= HTTP_ERROR_STATUS_400:
                                if self._should_try_next_media_upload_endpoint(
                                    response.status,
                                    endpoint_index,
                                    len(endpoints),
                                ):
                                    logger.warning(
                                        "Matrix media upload endpoint returned 404, "
                                        f"trying fallback endpoint: {endpoint}"
                                    )
                                    break

                                retry_after_seconds = self._extract_retry_after_seconds(
                                    response.headers, response_data
                                )
                                if (
                                    self._should_retry_http_status(response.status)
                                    and attempt < self._MEDIA_HTTP_MAX_RETRIES
                                ):
                                    delay = self._compute_retry_delay(
                                        attempt, retry_after_seconds
                                    )
                                    attempt += 1
                                    logger.warning(
                                        "Matrix media upload failed with status "
                                        f"{response.status}, retrying in {delay:.2f}s "
                                        f"({attempt}/{self._MEDIA_HTTP_MAX_RETRIES})"
                                    )
                                    await asyncio.sleep(delay)
                                    continue

                                error_code = response_data.get("errcode", "UNKNOWN")
                                error_msg = response_data.get("error", "Unknown error")
                                last_error = Exception(
                                    f"Matrix media upload error: {error_code} - {error_msg}"
                                )
                                raise last_error

                            content_uri = response_data.get("content_uri")
                            upload_id = response_data.get("upload_id")
                            if isinstance(content_uri, str) and content_uri:
                                # Synchronous upload
                                digest_cache_key = (
                                    self._build_media_upload_cache_key_from_digest(
                                        hashing_reader.hexdigest(),
                                        safe_content_type,
                                    )
                                )
                                self._save_upload_cache_result(
                                    path_cache_key, content_uri
                                )
                                self._save_upload_cache_result(
                                    digest_cache_key, content_uri
                                )
                                return response_data
                            elif isinstance(upload_id, str) and upload_id:
                                # Async upload (MSC2246) — poll until done
                                poll_response = await self._poll_upload_status(
                                    upload_id
                                )
                                poll_uri = poll_response.get("content_uri", "")
                                if isinstance(poll_uri, str) and poll_uri:
                                    self._save_upload_cache_result(
                                        path_cache_key, poll_uri
                                    )
                                    self._save_upload_cache_result(
                                        self._build_media_upload_cache_key_from_digest(
                                            hashing_reader.hexdigest(),
                                            safe_content_type,
                                        ),
                                        poll_uri,
                                    )
                                    return poll_response
                                last_error = Exception(
                                    f"Matrix async upload finished but missing "
                                    f"content_uri (upload_id={upload_id})"
                                )
                                raise last_error
                            else:
                                last_error = Exception(
                                    "Matrix media upload error: "
                                    "missing content_uri or upload_id in response"
                                )
                                raise last_error

                    except aiohttp.ClientError as e:
                        last_error = e
                        if attempt < self._MEDIA_HTTP_MAX_RETRIES:
                            delay = self._compute_retry_delay(attempt)
                            attempt += 1
                            logger.warning(
                                "Matrix media upload network error, retrying in "
                                f"{delay:.2f}s ({attempt}/{self._MEDIA_HTTP_MAX_RETRIES}): {e}"
                            )
                            await asyncio.sleep(delay)
                            continue
                        raise
                    finally:
                        if file_handle is not None:
                            await asyncio.to_thread(file_handle.close)

            if last_error is not None:
                raise last_error
            raise Exception("Matrix media upload error: no upload endpoint available")

        upload_task = asyncio.create_task(_perform_upload_from_path())
        self._media_upload_inflight[path_cache_key] = upload_task
        try:
            return await upload_task
        finally:
            current_task = self._media_upload_inflight.get(path_cache_key)
            if current_task is upload_task:
                self._media_upload_inflight.pop(path_cache_key, None)
