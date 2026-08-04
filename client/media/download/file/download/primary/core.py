"""Full-size Matrix media download orchestration."""

from pathlib import Path

from astrbot.api import logger

from ......path_utils import quote_path_segment


class MediaDownloadPrimaryCoreMixin:
    """Download full-size media from Matrix."""

    async def download_file(
        self,
        mxc_url: str,
        *,
        allow_thumbnail_fallback: bool = False,
        output_path: str | Path | None = None,
    ) -> bytes | None:
        """
        Download a file from the Matrix media repository
        按照 Matrix spec 正确实现媒体下载

        参考：https://spec.matrix.org/latest/client-server-api/#get_matrixclientv1mediadownloadservernamemediaid

        Args:
            mxc_url: MXC URL (mxc://server/media_id)
            allow_thumbnail_fallback: Whether to fallback to thumbnail on failure
            output_path: Optional local path to stream the response to

        Returns:
            File data as bytes, or None when output_path is provided
        """
        await self._ensure_session()
        resolved_output_path = Path(output_path) if output_path is not None else None

        server_name, media_id = self._parse_mxc_server_media_id(mxc_url)
        server_path = quote_path_segment(server_name)
        media_path = quote_path_segment(media_id)
        source_key = self._normalize_media_source_key(server_name)
        max_in_memory_bytes = self._get_media_download_max_in_memory_bytes()

        proxy_endpoints = [
            f"/_matrix/client/v1/media/download/{server_path}/{media_path}",
        ]
        direct_endpoints: list[str] = []
        public_endpoints: list[str] = []

        all_endpoints = (
            [(url, True, "proxy") for url in proxy_endpoints]
            + [(url, False, "direct") for url in direct_endpoints]
            + [(url, False, "public") for url in public_endpoints]
        )

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
                return payload

        if allow_thumbnail_fallback and last_status in [403, 404]:
            (
                fallback_succeeded,
                fallback_result,
            ) = await self._download_thumbnail_fallback(
                allow_thumbnail_fallback=allow_thumbnail_fallback,
                last_status=last_status,
                server_path=server_path,
                media_path=media_path,
                source_key=source_key,
                resolved_output_path=resolved_output_path,
                max_in_memory_bytes=max_in_memory_bytes,
                mxc_url=mxc_url,
            )
            if fallback_succeeded:
                return fallback_result
        error_msg = f"Matrix media download error: {last_error} (last status: {last_status}) for {mxc_url}"
        logger.error(error_msg)
        raise Exception(error_msg)
