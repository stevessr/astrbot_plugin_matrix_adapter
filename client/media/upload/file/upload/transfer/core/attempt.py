"""Single upload attempt execution."""

import asyncio
from pathlib import Path

import aiohttp

from ........constants import HTTP_ERROR_STATUS_400


class MediaUploadTransferAttemptMixin:
    """Execute one upload attempt with file-handle lifecycle."""

    async def _run_single_upload_attempt(
        self,
        *,
        url: str,
        headers: dict,
        params: dict,
        path: Path,
        path_cache_key: str,
        safe_content_type: str,
    ):
        """Run one request attempt; return a decision tuple.

        Returns ("success", payload) on success, ("status", status,
        response_data, response_headers) for an HTTP error, or
        ("client_error", error) for a network error.
        """
        file_handle = None
        try:
            file_handle = await asyncio.to_thread(path.open, "rb")
            hashing_reader = self._HashingFileReader(file_handle)
            (
                status,
                response_data,
                response_headers,
            ) = await self._post_upload_request_once(
                url,
                headers,
                params,
                hashing_reader,
            )

            if status >= HTTP_ERROR_STATUS_400:
                return ("status", status, response_data, response_headers)

            payload = await self._consume_upload_result(
                response_data,
                hashing_reader,
                path_cache_key,
                safe_content_type,
            )
            return ("success", payload)
        except aiohttp.ClientError as e:
            return ("client_error", e)
        finally:
            if file_handle is not None:
                await asyncio.to_thread(file_handle.close)


__all__ = ["MediaUploadTransferAttemptMixin"]
