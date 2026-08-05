"""Successful thumbnail download completion."""


class MediaDownloadThumbnailSuccessMixin:
    """Persist a successful thumbnail payload."""

    async def _complete_thumbnail_success(
        self,
        response,
        source_key,
        max_in_memory_bytes,
        mxc_url,
    ):
        await self._record_media_download_success(source_key)
        return (
            await self._read_response_with_memory_limit(
                response,
                max_in_memory_bytes=max_in_memory_bytes,
                resource_hint=mxc_url,
            ),
            None,
            None,
        )


__all__ = ["MediaDownloadThumbnailSuccessMixin"]
