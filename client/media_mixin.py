"""
Matrix HTTP Client - Media Mixin
Provides file upload and download methods
"""

from typing import Any

import aiohttp

from astrbot.api import logger

from ..constants import HTTP_ERROR_STATUS_400


class MediaMixin:
    """Media-related methods for Matrix client"""

    async def upload_file(
        self, data: bytes, content_type: str, filename: str
    ) -> dict[str, Any]:
        """
        Upload a file to the Matrix media repository

        Args:
            data: File data as bytes
            content_type: MIME type
            filename: Filename

        Returns:
            Upload response with content_uri
        """
        await self._ensure_session()

        url = f"{self.homeserver}/_matrix/media/v3/upload"
        headers = {
            "Content-Type": content_type,
            "Authorization": f"Bearer {self.access_token}",
            "User-Agent": "AstrBot Matrix Client/1.0",
        }
        params = {"filename": filename}

        async with self.session.post(
            url, data=data, headers=headers, params=params
        ) as response:
            response_data = await response.json()

            if response.status >= HTTP_ERROR_STATUS_400:
                error_code = response_data.get("errcode", "UNKNOWN")
                error_msg = response_data.get("error", "Unknown error")
                raise Exception(
                    f"Matrix media upload error: {error_code} - {error_msg}"
                )

            return response_data

    async def get_media_config(self) -> dict[str, Any]:
        """
        获取 Matrix 媒体服务器配置

        返回服务器的媒体配置，包括最大上传文件大小。
        参考：https://spec.matrix.org/latest/client-server-api/#get_matrixclientv1mediaconfig

        Returns:
            包含 m.upload.size 等配置的字典
        """
        await self._ensure_session()

        endpoint = "/_matrix/client/v1/media/config"
        try:
            url = f"{self.homeserver}{endpoint}"
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "User-Agent": "AstrBot Matrix Client/1.0",
            }

            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            logger.debug(f"获取媒体配置失败 ({endpoint}): {e}")

        # 如果所有端点都失败，返回空字典
        logger.warning("无法获取 Matrix 媒体服务器配置，将使用默认值")
        return {}

    async def download_file(self, mxc_url: str) -> bytes:
        """
        Download a file from the Matrix media repository
        按照 Matrix spec 正确实现媒体下载

        参考：https://spec.matrix.org/latest/client-server-api/#get_matrixclientv1mediadownloadservernamemediaid

        Args:
            mxc_url: MXC URL (mxc://server/media_id)

        Returns:
            File data as bytes
        """
        await self._ensure_session()

        # Parse MXC URL
        if not mxc_url.startswith("mxc://"):
            raise ValueError(f"Invalid MXC URL: {mxc_url}")

        parts = mxc_url[6:].split("/", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid MXC URL format: {mxc_url}")

        server_name, media_id = parts

        # 按照 Matrix spec，所有媒体下载都通过用户的 homeserver
        # 不管媒体来自哪个服务器，都使用认证请求
        # 参考：https://spec.matrix.org/latest/client-server-api/#id429

        # Try multiple download strategies
        # 1. 通过用户 homeserver 代理下载（需要认证）
        # 2. 缩略图作为最后手段

        # Strategy 1: 通过用户 homeserver 代理下载
        proxy_endpoints = [
            f"/_matrix/client/v1/media/download/{server_name}/{media_id}",
        ]

        # Strategy 2: 直接从源服务器下载（已在规范中弃用，移除）
        direct_endpoints: list[str] = []
        public_endpoints: list[str] = []

        all_endpoints = (
            [(url, True, "proxy") for url in proxy_endpoints]
            + [(url, False, "direct") for url in direct_endpoints]
            + [(url, False, "public") for url in public_endpoints]
        )

        last_error = None
        last_status = None

        for endpoint_info in all_endpoints:
            endpoint, use_auth, strategy = endpoint_info
            if use_auth:
                url = f"{self.homeserver}{endpoint}"
            else:
                url = endpoint

            # 根据策略决定是否使用认证
            headers = {"User-Agent": "AstrBot Matrix Client/1.0"}
            if use_auth and self.access_token:
                headers["Authorization"] = f"Bearer {self.access_token}"

            # 添加调试日志
            auth_status = (
                "with auth" if use_auth and self.access_token else "without auth"
            )
            logger.debug(f"Downloading from {url} {auth_status}")

            # 记录详细的下载策略
            logger.info(
                f"🎯 Attempting download from {url} {auth_status} (strategy: {strategy})"
            )

            try:
                logger.debug(f"Downloading media from: {url}")
                async with self.session.get(
                    url, headers=headers, allow_redirects=True
                ) as response:
                    last_status = response.status
                    if response.status == 200:
                        logger.debug(f"✅ Successfully downloaded media from {url}")
                        return await response.read()
                    elif response.status == 404:
                        logger.debug(f"Got 404 on {url}, trying next endpoint...")
                        last_error = f"Media not found: {response.status}"
                        continue
                    elif response.status == 403:
                        # 403 通常意味着认证问题或权限问题
                        logger.warning(
                            f"Got 403 on {url} (auth problem or private media)"
                        )
                        last_error = f"Access denied: {response.status}"
                        continue
                    else:
                        last_error = f"HTTP {response.status}"
                        logger.debug(f"Got status {response.status} from {url}")
            except aiohttp.ClientError as e:
                last_error = str(e)
                logger.debug(f"Network error downloading from {url}: {e}")
                continue
            except Exception as e:
                last_error = str(e)
                logger.debug(f"Exception downloading from {url}: {e}")
                continue

        # 所有端点都失败了，尝试缩略图作为最后手段
        if last_status in [403, 404]:
            logger.debug("Trying thumbnail endpoints as fallback...")
            thumbnail_endpoints = [
                f"/_matrix/client/v1/media/thumbnail/{server_name}/{media_id}?width=800&height=600",
            ]

            for endpoint in thumbnail_endpoints:
                url = f"{self.homeserver}{endpoint}"
                headers = {"User-Agent": "AstrBot Matrix Client/1.0"}
                if self.access_token:
                    headers["Authorization"] = f"Bearer {self.access_token}"

                try:
                    async with self.session.get(
                        url, headers=headers, allow_redirects=True
                    ) as response:
                        if response.status == 200:
                            logger.info("✅ Downloaded thumbnail instead of full media")
                            return await response.read()
                except Exception:
                    continue

        # If all attempts failed, raise the last error
        error_msg = f"Matrix media download error: {last_error} (last status: {last_status}) for {mxc_url}"
        logger.error(error_msg)
        raise Exception(error_msg)

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

        if not mxc_url.startswith("mxc://"):
            raise ValueError(f"Invalid MXC URL: {mxc_url}")

        parts = mxc_url[6:].split("/", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid MXC URL format: {mxc_url}")

        server_name, media_id = parts
        query = f"width={width}&height={height}"
        if method:
            query += f"&method={method}"
        if animated is not None:
            query += f"&animated={'true' if animated else 'false'}"

        endpoints = [
            f"/_matrix/client/v1/media/thumbnail/{server_name}/{media_id}?{query}",
        ]

        last_error = None
        last_status = None

        for endpoint in endpoints:
            url = f"{self.homeserver}{endpoint}"
            headers = {"User-Agent": "AstrBot Matrix Client/1.0"}
            if self.access_token:
                headers["Authorization"] = f"Bearer {self.access_token}"

            try:
                async with self.session.get(
                    url, headers=headers, allow_redirects=True
                ) as response:
                    last_status = response.status
                    if response.status == 200:
                        return await response.read()
                    last_error = f"HTTP {response.status}"
            except Exception as e:
                last_error = str(e)
                continue

        error_msg = (
            f"Matrix thumbnail error: {last_error} (last status: {last_status}) "
            f"for {mxc_url}"
        )
        logger.error(error_msg)
        raise Exception(error_msg)

    async def get_url_preview(
        self, url: str, timestamp_ms: int | None = None
    ) -> dict[str, Any]:
        """
        Get URL preview metadata

        Args:
            url: URL to preview
            timestamp_ms: Optional timestamp in milliseconds

        Returns:
            Preview response
        """
        params: dict[str, Any] = {"url": url}
        if timestamp_ms is not None:
            params["ts"] = timestamp_ms

        endpoints = ["/_matrix/client/v1/media/preview_url"]

        last_error: Exception | None = None
        for endpoint in endpoints:
            try:
                return await self._request("GET", endpoint, params=params)
            except Exception as e:
                last_error = e
                continue

        raise Exception(f"Matrix URL preview error: {last_error}")
