"""Response streaming helpers for media downloads."""

import time
from pathlib import Path

import aiohttp


class MediaDownloadResponseMixin:
    """Read or stream Matrix media responses safely."""

    @staticmethod
    def _get_content_length(response: aiohttp.ClientResponse) -> int | None:
        header = response.headers.get("Content-Length")
        if header is None:
            return None
        try:
            parsed = int(header)
        except Exception:
            return None
        if parsed < 0:
            return None
        return parsed

    async def _read_response_with_memory_limit(
        self,
        response: aiohttp.ClientResponse,
        *,
        max_in_memory_bytes: int,
        resource_hint: str,
    ) -> bytes:
        if max_in_memory_bytes <= 0:
            return await response.read()

        content_length = self._get_content_length(response)
        if content_length is not None and content_length > max_in_memory_bytes:
            raise ValueError(
                "Matrix media download exceeds in-memory limit before reading "
                f"(content_length={content_length}, limit={max_in_memory_bytes}, "
                f"resource={resource_hint})"
            )

        buffer = bytearray()
        async for chunk in response.content.iter_chunked(64 * 1024):
            if not chunk:
                continue
            buffer.extend(chunk)
            if len(buffer) > max_in_memory_bytes:
                raise ValueError(
                    "Matrix media download exceeds in-memory limit while reading "
                    f"(read={len(buffer)}, limit={max_in_memory_bytes}, "
                    f"resource={resource_hint})"
                )

        return bytes(buffer)

    async def _save_response_to_path(
        self, response: aiohttp.ClientResponse, output_path: Path
    ) -> None:
        temp_path = output_path.with_name(f".{output_path.name}.{time.time_ns()}.tmp")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with temp_path.open("wb") as f:
                async for chunk in response.content.iter_chunked(64 * 1024):
                    if chunk:
                        f.write(chunk)
            temp_path.replace(output_path)
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise
