"""Successful media download completion."""

from astrbot.api import logger


class MediaDownloadAttemptSuccessMixin:
    """Persist a successful download payload or stream it to disk."""

    async def _complete_successful_download(
        self,
        url,
        response,
        *,
        source_key,
        resolved_output_path,
        max_in_memory_bytes,
        mxc_url,
    ):
        await self._record_media_download_success(source_key)
        logger.debug(f"Successfully downloaded media from {url}")
        if resolved_output_path is not None:
            await self._save_response_to_path(response, resolved_output_path)
            return None, 200, None
        payload = await self._read_response_with_memory_limit(
            response,
            max_in_memory_bytes=max_in_memory_bytes,
            resource_hint=mxc_url,
        )
        return None, 200, payload


__all__ = ["MediaDownloadAttemptSuccessMixin"]
