"""Thumbnail fallback for full-size Matrix media downloads."""

from pathlib import Path

from astrbot.api import logger


class MediaDownloadThumbnailFallbackOrchestratorMixin:
    """Retry media downloads through thumbnail endpoints."""

    async def _download_thumbnail_fallback(
        self,
        *,
        allow_thumbnail_fallback: bool,
        last_status: int | None,
        server_path: str,
        media_path: str,
        source_key: str,
        resolved_output_path: Path | None,
        max_in_memory_bytes: int | None,
        mxc_url: str,
    ) -> tuple[bool, bytes | None]:
        if allow_thumbnail_fallback and last_status in [403, 404]:
            logger.debug("Trying thumbnail endpoints as fallback...")
            thumbnail_endpoints = [
                self._build_thumbnail_endpoint_url(server_path, media_path),
            ]

            for endpoint in thumbnail_endpoints:
                url = f"{self.homeserver}{endpoint}"
                headers = self._build_thumbnail_request_headers()

                downloaded, payload = await self._attempt_thumbnail_download(
                    url=url,
                    headers=headers,
                    source_key=source_key,
                    resolved_output_path=resolved_output_path,
                    max_in_memory_bytes=max_in_memory_bytes,
                    mxc_url=mxc_url,
                )
                if downloaded:
                    return True, payload
        return False, None


__all__ = ["MediaDownloadThumbnailFallbackOrchestratorMixin"]
