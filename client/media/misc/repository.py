"""Matrix media repository helpers."""

from typing import Any

from astrbot.api import logger


class MediaRepositoryMixin:
    """Handle MXC identifiers and media repository configuration."""

    @staticmethod
    def _parse_mxc_server_media_id(mxc_url: str) -> tuple[str, str]:
        """Parse an ``mxc://server/media`` URI into Matrix path segments.

        Some bridges and clients append query strings or fragments to MXC
        references for local UI hints.  The Matrix media repository path only
        accepts the server name and media ID, so strip those suffixes before
        percent-encoding each segment.
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
