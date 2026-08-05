"""Full-size Matrix media download orchestration."""

from pathlib import Path

from astrbot.api import logger


class MediaDownloadPrimaryOrchestratorMixin:
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
        (
            resolved_output_path,
            server_path,
            media_path,
            source_key,
            max_in_memory_bytes,
        ) = await self._prepare_download(mxc_url, output_path)

        all_endpoints = self._build_download_endpoint_list(server_path, media_path)

        payload, last_error, last_status = await self._attempt_download_from_endpoints(
            all_endpoints,
            source_key,
            mxc_url,
            resolved_output_path,
            max_in_memory_bytes,
        )
        if last_status == 200:
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


__all__ = ["MediaDownloadPrimaryOrchestratorMixin"]
