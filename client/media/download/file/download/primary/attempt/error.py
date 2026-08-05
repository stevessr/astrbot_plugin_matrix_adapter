"""Final error reporting for unsuccessful media downloads."""

from astrbot.api import logger


class MediaDownloadAttemptErrorMixin:
    """Describe and record the terminal HTTP failure."""

    async def _finalize_http_error(self, url, response, source_key):
        if self._is_media_download_breaker_failure_status(response.status):
            await self._record_media_download_failure(source_key, response.status)
        if response.status == 404:
            last_error = f"Media not found: {response.status}"
        elif response.status == 403:
            last_error = f"Access denied: {response.status}"
            logger.debug(f"Got 403 on {url} (auth problem or private media)")
        else:
            last_error = f"HTTP {response.status}"
        return last_error


__all__ = ["MediaDownloadAttemptErrorMixin"]
