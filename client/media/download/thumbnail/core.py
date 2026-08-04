"""Matrix media thumbnail download entry orchestration."""

from typing import Any
from urllib.parse import urlencode

from astrbot.api import logger

from ....path_utils import quote_path_segment


class MediaDownloadThumbnailCoreMixin:
    """Download thumbnails: build request and dispatch the transfer."""

    async def get_thumbnail(
        self,
        mxc_url: str,
        width: int,
        height: int,
        method: str | None = None,
        animated: bool | None = None,
    ) -> bytes:
        """
        Get a thumbnail for media

        Args:
            mxc_url: MXC URL (mxc://server/media_id)
            width: Thumbnail width
            height: Thumbnail height
            method: Optional method (crop, scale)
            animated: Optional animated flag

        Returns:
            Thumbnail bytes
        """
        await self._ensure_session()

        server_name, media_id = self._parse_mxc_server_media_id(mxc_url)
        server_path = quote_path_segment(server_name)
        media_path = quote_path_segment(media_id)
        source_key = self._normalize_media_source_key(server_name)
        max_in_memory_bytes = self._get_media_download_max_in_memory_bytes()
        query_params: dict[str, Any] = {"width": width, "height": height}
        if method:
            query_params["method"] = method
        if animated is not None:
            query_params["animated"] = "true" if animated else "false"
        query = urlencode(query_params)

        url = (
            f"{self.homeserver}/_matrix/client/v1/media/thumbnail/"
            f"{server_path}/{media_path}?{query}"
        )

        result, last_error, last_status = await self._perform_thumbnail_download(
            url=url,
            source_key=source_key,
            max_in_memory_bytes=max_in_memory_bytes,
            mxc_url=mxc_url,
        )
        if result is not None:
            return result

        error_msg = (
            f"Matrix thumbnail error: {last_error} (last status: {last_status}) "
            f"for {mxc_url}"
        )
        logger.error(error_msg)
        raise Exception(error_msg)
