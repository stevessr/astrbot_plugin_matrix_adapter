"""
Matrix HTTP Client - Media Upload Mixin
Provides file upload methods
"""

import asyncio
import hashlib
import time
from pathlib import Path
from typing import Any

import aiohttp

from astrbot.api import logger

from ...constants import HTTP_ERROR_STATUS_400
from ..base import MatrixAPIError
from ..path_utils import quote_path_segment


class MediaUploadMixin:
    """Media upload methods for Matrix client"""

    _MEDIA_UPLOAD_CACHE_TTL_SECONDS = 15 * 60

    _MEDIA_UPLOAD_CACHE_MAX_ENTRIES = 256

    _MEDIA_HTTP_MAX_RETRIES = 3

    _MEDIA_RETRY_BASE_DELAY_SECONDS = 0.75

    _MEDIA_RETRY_MAX_DELAY_SECONDS = 10.0

    _MEDIA_UPLOAD_SNIFF_BYTES = 4096

    _MEDIA_UPLOAD_POLL_TIMEOUT_SECONDS = 120.0

    _MEDIA_UPLOAD_POLL_INTERVAL_SECONDS = 0.5

    def _ensure_media_upload_cache(self) -> None:
        if not hasattr(self, "_media_upload_cache"):
            self._media_upload_cache: dict[str, tuple[str, float]] = {}
        if not hasattr(self, "_media_upload_inflight"):
            self._media_upload_inflight: dict[str, asyncio.Task[dict[str, Any]]] = {}

    @staticmethod
    def _build_media_upload_cache_key(data: bytes, content_type: str) -> str:
        digest = hashlib.sha256(data).hexdigest()
        return f"{content_type}:{digest}"

    @staticmethod
    def _build_media_upload_cache_key_from_digest(
        digest: str, content_type: str
    ) -> str:
        return f"{content_type}:{digest}"

    @staticmethod
    def _build_media_upload_cache_key_from_file_state(
        file_path: Path,
        content_type: str,
    ) -> str:
        stat_result = file_path.stat()
        identity = (
            f"{file_path.resolve()}:{stat_result.st_dev}:{stat_result.st_ino}:"
            f"{stat_result.st_size}:{stat_result.st_mtime_ns}"
        )
        digest = hashlib.sha256(identity.encode("utf-8", errors="ignore")).hexdigest()
        return f"{content_type}:path:{digest}"

    def _prune_media_upload_cache(self, now: float) -> None:
        expired_keys = [
            key
            for key, (_, ts) in self._media_upload_cache.items()
            if (now - ts) > self._MEDIA_UPLOAD_CACHE_TTL_SECONDS
        ]
        for key in expired_keys:
            self._media_upload_cache.pop(key, None)

        overflow = len(self._media_upload_cache) - self._MEDIA_UPLOAD_CACHE_MAX_ENTRIES
        if overflow <= 0:
            return

        oldest_keys = sorted(
            self._media_upload_cache.items(),
            key=lambda item: item[1][1],
        )[:overflow]
        for key, _ in oldest_keys:
            self._media_upload_cache.pop(key, None)

    @staticmethod
    def _coerce_retry_after_seconds(value: Any) -> float | None:
        if value is None:
            return None
        try:
            retry_after = float(value)
        except (TypeError, ValueError):
            return None
        if retry_after <= 0:
            return None
        return retry_after

    def _extract_retry_after_seconds(
        self,
        response_headers: "aiohttp.typedefs.LooseHeaders",
        response_data: dict[str, Any] | None = None,
    ) -> float | None:
        retry_after = self._coerce_retry_after_seconds(
            (response_data or {}).get("retry_after_ms")
        )
        if retry_after is not None:
            return min(retry_after / 1000.0, self._MEDIA_RETRY_MAX_DELAY_SECONDS)

        header_value = None
        try:
            header_value = response_headers.get("Retry-After")
        except Exception:
            header_value = None
        retry_after_header = self._coerce_retry_after_seconds(header_value)
        if retry_after_header is None:
            return None
        return min(retry_after_header, self._MEDIA_RETRY_MAX_DELAY_SECONDS)

    def _compute_retry_delay(
        self, attempt: int, retry_after_seconds: float | None = None
    ) -> float:
        if retry_after_seconds is not None:
            return max(0.1, retry_after_seconds)
        return min(
            self._MEDIA_RETRY_BASE_DELAY_SECONDS * (2**attempt),
            self._MEDIA_RETRY_MAX_DELAY_SECONDS,
        )

    @staticmethod
    def _should_retry_http_status(status: int) -> bool:
        return status == 429 or status >= 500

    @staticmethod
    def _get_media_upload_endpoints() -> tuple[str, ...]:
        """Return preferred media upload endpoints in compatibility order."""
        return (
            "/_matrix/client/v1/media/upload",
            "/_matrix/media/v3/upload",
        )

    @staticmethod
    def _get_media_upload_status_endpoint(upload_id: str) -> str:
        """Return the upload status endpoint for async upload (MSC2246)."""
        return f"/_matrix/client/v1/media/upload/{quote_path_segment(upload_id)}"

    async def _poll_upload_status(self, upload_id: str) -> dict[str, Any]:
        """
        Poll the upload status endpoint until the async upload completes
        (MSC2246 asynchronous media uploads).

        Returns the final response dict containing ``content_uri``.
        """
        endpoint = self._get_media_upload_status_endpoint(upload_id)
        deadline = time.monotonic() + self._MEDIA_UPLOAD_POLL_TIMEOUT_SECONDS

        while time.monotonic() < deadline:
            try:
                response = await self._request("GET", endpoint)
                status = response.get("status", "")
                if status == "done":
                    content_uri = response.get("content_uri", "")
                    if content_uri:
                        return response
                    raise Exception("Matrix async upload done but missing content_uri")
                if status in ("failed", "cancelled"):
                    error_msg = response.get("error", "unknown error")
                    raise Exception(f"Matrix async upload {status}: {error_msg}")
                # Still pending — wait and retry
                await asyncio.sleep(self._MEDIA_UPLOAD_POLL_INTERVAL_SECONDS)
            except MatrixAPIError:
                raise
            except Exception:
                await asyncio.sleep(self._MEDIA_UPLOAD_POLL_INTERVAL_SECONDS)

        raise Exception(
            f"Matrix async upload timed out after "
            f"{self._MEDIA_UPLOAD_POLL_TIMEOUT_SECONDS}s (upload_id={upload_id})"
        )

    @staticmethod
    def _should_try_next_media_upload_endpoint(
        status: int,
        endpoint_index: int,
        total_endpoints: int,
    ) -> bool:
        return status == 404 and endpoint_index < (total_endpoints - 1)

    def _get_cached_upload_result(self, cache_key: str) -> dict[str, Any] | None:
        now = time.monotonic()
        cached = self._media_upload_cache.get(cache_key)
        if cached and (now - cached[1]) <= self._MEDIA_UPLOAD_CACHE_TTL_SECONDS:
            logger.debug(
                "Reusing recent Matrix media upload result from in-memory cache"
            )
            return {"content_uri": cached[0]}
        return None

    def _save_upload_cache_result(self, cache_key: str, content_uri: str) -> None:
        now_inner = time.monotonic()
        self._media_upload_cache[cache_key] = (content_uri, now_inner)
        self._prune_media_upload_cache(now_inner)

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
            headers = {
                "Content-Type": safe_content_type,
                "Authorization": f"Bearer {self.access_token}",
                "User-Agent": "AstrBot Matrix Client/1.0",
            }
            params = {"filename": filename}
            endpoints = self._get_media_upload_endpoints()
            last_error: Exception | None = None

            for endpoint_index, endpoint in enumerate(endpoints):
                url = f"{self.homeserver}{endpoint}"
                attempt = 0

                while True:
                    try:
                        async with self.session.post(
                            url, data=data, headers=headers, params=params
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
                                        "trying fallback endpoint: %s",
                                        endpoint,
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
                                # Synchronous upload — content_uri available immediately
                                self._save_upload_cache_result(cache_key, content_uri)
                                return response_data
                            elif isinstance(upload_id, str) and upload_id:
                                # Async upload (MSC2246) — poll until done
                                poll_response = await self._poll_upload_status(
                                    upload_id
                                )
                                poll_uri = poll_response.get("content_uri", "")
                                if isinstance(poll_uri, str) and poll_uri:
                                    self._save_upload_cache_result(cache_key, poll_uri)
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

            if last_error is not None:
                raise last_error
            raise Exception("Matrix media upload error: no upload endpoint available")

        upload_task = asyncio.create_task(_perform_upload())
        self._media_upload_inflight[cache_key] = upload_task
        try:
            return await upload_task
        finally:
            current_task = self._media_upload_inflight.get(cache_key)
            if current_task is upload_task:
                self._media_upload_inflight.pop(cache_key, None)

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
