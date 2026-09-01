"""Matrix media repository helpers."""

import re
from typing import Any

from astrbot.api import logger

_MXC_MEDIA_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class MediaRepositoryMixin:
    """Handle MXC identifiers and media repository configuration."""

    @staticmethod
    def _parse_mxc_server_media_id(mxc_url: str) -> tuple[str, str]:
        """Parse an ``mxc://server/media`` URI into Matrix path segments.

        Matrix v1.19 clarifies that the opaque ``media-id`` contains only
        ``A-Za-z0-9``, ``_`` and ``-``.  Query strings/fragments sometimes
        appear as non-standard local UI hints, so they are stripped before the
        stable media-id grammar is validated.
        """
        if not isinstance(mxc_url, str) or not mxc_url.startswith("mxc://"):
            raise ValueError(f"Invalid MXC URL: {mxc_url}")

        parts = mxc_url[6:].split("/", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid MXC URL format: {mxc_url}")

        server_name = parts[0].strip()
        media_id = parts[1].split("?", 1)[0].split("#", 1)[0].strip().lstrip("/")
        if not server_name or not media_id:
            raise ValueError(f"Invalid MXC URL format: {mxc_url}")
        if _MXC_MEDIA_ID_RE.fullmatch(media_id) is None:
            raise ValueError(f"Invalid MXC media ID: {mxc_url}")
        return server_name, media_id

    async def get_media_config(self) -> dict[str, Any]:
        """
        获取 Matrix 媒体服务器配置

        返回服务器的媒体配置，包括最大上传文件大小。
        参考：https://spec.matrix.org/latest/client-server-api/#get_matrixclientv1mediaconfig

        Returns:
            包含 m.upload.size 等配置的字典
        """
        endpoint = "/_matrix/client/v1/media/config"
        try:
            return await self._request("GET", endpoint)
        except Exception as e:
            logger.debug(f"获取媒体配置失败 ({endpoint}): {e}")

        logger.warning("无法获取 Matrix 媒体服务器配置，将使用默认值")
        return {}
