"""Full-size Matrix media download attempt loop."""

from astrbot.api import logger


class MediaDownloadPrimaryAttemptMixin:
    """Attempt media downloads across endpoints in order."""

    async def _attempt_download_from_endpoints(
        self,
        all_endpoints: list,
        source_key: str,
        mxc_url: str,
        resolved_output_path,
        max_in_memory_bytes: int,
    ):
        """Return (payload, last_error, last_status) after trying endpoints."""
        last_error = None
        last_status = None

        for endpoint, use_auth, strategy in all_endpoints:
            if use_auth:
                url = f"{self.homeserver}{endpoint}"
            else:
                url = endpoint

            headers = {"User-Agent": "AstrBot Matrix Client/1.0"}
            if use_auth and self.access_token:
                headers["Authorization"] = f"Bearer {self.access_token}"

            auth_status = (
                "with auth" if use_auth and self.access_token else "without auth"
            )
            logger.debug(
                f"Attempting media download from {url} {auth_status} (strategy: {strategy})"
            )

            error, status, payload = await self._download_from_endpoint(
                url,
                headers,
                source_key=source_key,
                mxc_url=mxc_url,
                resolved_output_path=resolved_output_path,
                max_in_memory_bytes=max_in_memory_bytes,
            )
            last_error = error
            last_status = status
            if status == 200:
                return payload, last_error, last_status

        return None, last_error, last_status


__all__ = ["MediaDownloadPrimaryAttemptMixin"]
