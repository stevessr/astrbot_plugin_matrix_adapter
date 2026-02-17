"""
Matrix HTTP Client - Media Mixin
Provides file upload and download methods
"""

import asyncio
import hashlib
import time
from pathlib import Path
from typing import Any

import aiohttp

from astrbot.api import logger

from ..constants import HTTP_ERROR_STATUS_400


class MediaMixin:
    """Media-related methods for Matrix client"""

    _MEDIA_UPLOAD_CACHE_TTL_SECONDS = 15 * 60
    _MEDIA_UPLOAD_CACHE_MAX_ENTRIES = 256
    _MEDIA_HTTP_MAX_RETRIES = 3
    _MEDIA_RETRY_BASE_DELAY_SECONDS = 0.75
    _MEDIA_RETRY_MAX_DELAY_SECONDS = 10.0

    def _ensure_media_upload_cache(self) -> None:
        if not hasattr(self, "_media_upload_cache"):
            self._media_upload_cache: dict[str, tuple[str, float]] = {}
        if not hasattr(self, "_media_upload_inflight"):
            self._media_upload_inflight: dict[str, asyncio.Task[dict[str, Any]]] = {}

    @staticmethod
    def _build_media_upload_cache_key(data: bytes, content_type: str) -> str:
        digest = hashlib.sha256(data).hexdigest()
        return f"{content_type}:{digest}"

    @staticmethod
    def _build_media_upload_cache_key_from_digest(
        digest: str, content_type: str
    ) -> str:
        return f"{content_type}:{digest}"

    @staticmethod
    def _sha256_file(file_path: Path, chunk_size: int = 1024 * 1024) -> str:
        hasher = hashlib.sha256()
        with file_path.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()

    def _prune_media_upload_cache(self, now: float) -> None:
        expired_keys = [
            key
            for key, (_, ts) in self._media_upload_cache.items()
            if (now - ts) > self._MEDIA_UPLOAD_CACHE_TTL_SECONDS
        ]
        for key in expired_keys:
            self._media_upload_cache.pop(key, None)

        overflow = len(self._media_upload_cache) - self._MEDIA_UPLOAD_CACHE_MAX_ENTRIES
        if overflow <= 0:
            return

        oldest_keys = sorted(
            self._media_upload_cache.items(),
            key=lambda item: item[1][1],
        )[:overflow]
        for key, _ in oldest_keys:
            self._media_upload_cache.pop(key, None)

    @staticmethod
    def _coerce_retry_after_seconds(value: Any) -> float | None:
        if value is None:
            return None
        try:
            retry_after = float(value)
        except (TypeError, ValueError):
            return None
        if retry_after <= 0:
            return None
        return retry_after

    def _extract_retry_after_seconds(
        self,
        response_headers: "aiohttp.typedefs.LooseHeaders",
        response_data: dict[str, Any] | None = None,
    ) -> float | None:
        retry_after = self._coerce_retry_after_seconds(
            (response_data or {}).get("retry_after_ms")
        )
        if retry_after is not None:
            return min(retry_after / 1000.0, self._MEDIA_RETRY_MAX_DELAY_SECONDS)

        header_value = None
        try:
            header_value = response_headers.get("Retry-After")
        except Exception:
            header_value = None
        retry_after_header = self._coerce_retry_after_seconds(header_value)
        if retry_after_header is None:
            return None
        return min(retry_after_header, self._MEDIA_RETRY_MAX_DELAY_SECONDS)

    def _compute_retry_delay(
        self, attempt: int, retry_after_seconds: float | None = None
    ) -> float:
        if retry_after_seconds is not None:
            return max(0.1, retry_after_seconds)
        return min(
            self._MEDIA_RETRY_BASE_DELAY_SECONDS * (2**attempt),
            self._MEDIA_RETRY_MAX_DELAY_SECONDS,
        )

    @staticmethod
    def _should_retry_http_status(status: int) -> bool:
        return status == 429 or status >= 500

    def _get_cached_upload_result(self, cache_key: str) -> dict[str, Any] | None:
        now = time.monotonic()
        cached = self._media_upload_cache.get(cache_key)
        if cached and (now - cached[1]) <= self._MEDIA_UPLOAD_CACHE_TTL_SECONDS:
            logger.debug(
                "Reusing recent Matrix media upload result from in-memory cache"
            )
            return {"content_uri": cached[0]}
        return None

    def _save_upload_cache_result(self, cache_key: str, content_uri: str) -> None:
        now_inner = time.monotonic()
        self._media_upload_cache[cache_key] = (content_uri, now_inner)
        self._prune_media_upload_cache(now_inner)

    async def _save_response_to_path(
        self, response: aiohttp.ClientResponse, output_path: Path
    ) -> None:
        temp_path = output_path.with_name(f".{output_path.name}.{time.time_ns()}.tmp")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with temp_path.open("wb") as f:
            async for chunk in response.content.iter_chunked(64 * 1024):
                if chunk:
                    f.write(chunk)
        temp_path.replace(output_path)

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
        self._ensure_media_upload_cache()

        cache_key = self._build_media_upload_cache_key(data, content_type)
        cached_response = self._get_cached_upload_result(cache_key)
        if cached_response:
            return cached_response

        existing_task = self._media_upload_inflight.get(cache_key)
        if existing_task:
            logger.debug("Joining in-flight Matrix media upload task")
            return await existing_task

        async def _perform_upload() -> dict[str, Any]:
            url = f"{self.homeserver}/_matrix/media/v3/upload"
            headers = {
                "Content-Type": content_type,
                "Authorization": f"Bearer {self.access_token}",
                "User-Agent": "AstrBot Matrix Client/1.0",
            }
            params = {"filename": filename}
            attempt = 0
            while True:
                try:
                    async with self.session.post(
                        url, data=data, headers=headers, params=params
                    ) as response:
                        response_data: dict[str, Any] = {}
                        try:
                            parsed = await response.json(content_type=None)
                            if isinstance(parsed, dict):
                                response_data = parsed
                        except Exception:
                            try:
                                response_data = {"error": await response.text()}
                            except Exception:
                                response_data = {}

                        if response.status >= HTTP_ERROR_STATUS_400:
                            retry_after_seconds = self._extract_retry_after_seconds(
                                response.headers, response_data
                            )
                            if (
                                self._should_retry_http_status(response.status)
                                and attempt < self._MEDIA_HTTP_MAX_RETRIES
                            ):
                                delay = self._compute_retry_delay(
                                    attempt, retry_after_seconds
                                )
                                attempt += 1
                                logger.warning(
                                    "Matrix media upload failed with status "
                                    f"{response.status}, retrying in {delay:.2f}s "
                                    f"({attempt}/{self._MEDIA_HTTP_MAX_RETRIES})"
                                )
                                await asyncio.sleep(delay)
                                continue

                            error_code = response_data.get("errcode", "UNKNOWN")
                            error_msg = response_data.get("error", "Unknown error")
                            raise Exception(
                                f"Matrix media upload error: {error_code} - {error_msg}"
                            )

                        content_uri = response_data.get("content_uri")
                        if not isinstance(content_uri, str) or not content_uri:
                            raise Exception(
                                "Matrix media upload error: missing content_uri"
                            )

                        self._save_upload_cache_result(cache_key, content_uri)
                        return response_data

                except aiohttp.ClientError as e:
                    if attempt < self._MEDIA_HTTP_MAX_RETRIES:
                        delay = self._compute_retry_delay(attempt)
                        attempt += 1
                        logger.warning(
                            "Matrix media upload network error, retrying in "
                            f"{delay:.2f}s ({attempt}/{self._MEDIA_HTTP_MAX_RETRIES}): {e}"
                        )
                        await asyncio.sleep(delay)
                        continue
                    raise

        upload_task = asyncio.create_task(_perform_upload())
        self._media_upload_inflight[cache_key] = upload_task
        try:
            return await upload_task
        finally:
            current_task = self._media_upload_inflight.get(cache_key)
            if current_task is upload_task:
                self._media_upload_inflight.pop(cache_key, None)

    async def upload_file_path(
        self, file_path: str | Path, content_type: str, filename: str | None = None
    ) -> dict[str, Any]:
        """
        Upload a local file to the Matrix media repository without loading it fully
        into memory.
        """
        await self._ensure_session()
        self._ensure_media_upload_cache()

        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(
                f"Matrix media upload source file not found: {path}"
            )

        digest = await asyncio.to_thread(self._sha256_file, path)
        cache_key = self._build_media_upload_cache_key_from_digest(digest, content_type)
        cached_response = self._get_cached_upload_result(cache_key)
        if cached_response:
            return cached_response

        existing_task = self._media_upload_inflight.get(cache_key)
        if existing_task:
            logger.debug("Joining in-flight Matrix media upload task")
            return await existing_task

        upload_filename = filename or path.name

        async def _perform_upload_from_path() -> dict[str, Any]:
            url = f"{self.homeserver}/_matrix/media/v3/upload"
            headers = {
                "Content-Type": content_type,
                "Authorization": f"Bearer {self.access_token}",
                "User-Agent": "AstrBot Matrix Client/1.0",
            }
            params = {"filename": upload_filename}
            attempt = 0

            while True:
                try:
                    with path.open("rb") as file_handle:
                        async with self.session.post(
                            url, data=file_handle, headers=headers, params=params
                        ) as response:
                            response_data: dict[str, Any] = {}
                            try:
                                parsed = await response.json(content_type=None)
                                if isinstance(parsed, dict):
                                    response_data = parsed
                            except Exception:
                                try:
                                    response_data = {"error": await response.text()}
                                except Exception:
                                    response_data = {}

                            if response.status >= HTTP_ERROR_STATUS_400:
                                retry_after_seconds = self._extract_retry_after_seconds(
                                    response.headers, response_data
                                )
                                if (
                                    self._should_retry_http_status(response.status)
                                    and attempt < self._MEDIA_HTTP_MAX_RETRIES
                                ):
                                    delay = self._compute_retry_delay(
                                        attempt, retry_after_seconds
                                    )
                                    attempt += 1
                                    logger.warning(
                                        "Matrix media upload failed with status "
                                        f"{response.status}, retrying in {delay:.2f}s "
                                        f"({attempt}/{self._MEDIA_HTTP_MAX_RETRIES})"
                                    )
                                    await asyncio.sleep(delay)
                                    continue

                                error_code = response_data.get("errcode", "UNKNOWN")
                                error_msg = response_data.get("error", "Unknown error")
                                raise Exception(
                                    f"Matrix media upload error: {error_code} - {error_msg}"
                                )

                            content_uri = response_data.get("content_uri")
                            if not isinstance(content_uri, str) or not content_uri:
                                raise Exception(
                                    "Matrix media upload error: missing content_uri"
                                )

                            self._save_upload_cache_result(cache_key, content_uri)
                            return response_data

                except aiohttp.ClientError as e:
                    if attempt < self._MEDIA_HTTP_MAX_RETRIES:
                        delay = self._compute_retry_delay(attempt)
                        attempt += 1
                        logger.warning(
                            "Matrix media upload network error, retrying in "
                            f"{delay:.2f}s ({attempt}/{self._MEDIA_HTTP_MAX_RETRIES}): {e}"
                        )
                        await asyncio.sleep(delay)
                        continue
                    raise

        upload_task = asyncio.create_task(_perform_upload_from_path())
        self._media_upload_inflight[cache_key] = upload_task
        try:
            return await upload_task
        finally:
            current_task = self._media_upload_inflight.get(cache_key)
            if current_task is upload_task:
                self._media_upload_inflight.pop(cache_key, None)

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

            auth_status = (
                "with auth" if use_auth and self.access_token else "without auth"
            )
            logger.debug(
                f"Attempting media download from {url} {auth_status} (strategy: {strategy})"
            )

            attempt = 0
            while True:
                try:
                    async with self.session.get(
                        url, headers=headers, allow_redirects=True
                    ) as response:
                        last_status = response.status
                        if response.status == 200:
                            logger.debug(f"Successfully downloaded media from {url}")
                            if resolved_output_path is not None:
                                await self._save_response_to_path(
                                    response, resolved_output_path
                                )
                                return None
                            return await response.read()

                        retry_after_seconds = None
                        if response.status == 429:
                            retry_payload: dict[str, Any] = {}
                            try:
                                parsed = await response.json(content_type=None)
                                if isinstance(parsed, dict):
                                    retry_payload = parsed
                            except Exception:
                                retry_payload = {}
                            retry_after_seconds = self._extract_retry_after_seconds(
                                response.headers, retry_payload
                            )
                        elif response.status >= 500:
                            retry_after_seconds = self._extract_retry_after_seconds(
                                response.headers, None
                            )

                        if (
                            self._should_retry_http_status(response.status)
                            and attempt < self._MEDIA_HTTP_MAX_RETRIES
                        ):
                            delay = self._compute_retry_delay(
                                attempt, retry_after_seconds
                            )
                            attempt += 1
                            logger.warning(
                                "Matrix media download failed with status "
                                f"{response.status}, retrying in {delay:.2f}s "
                                f"({attempt}/{self._MEDIA_HTTP_MAX_RETRIES})"
                            )
                            await asyncio.sleep(delay)
                            continue

                        if response.status == 404:
                            last_error = f"Media not found: {response.status}"
                        elif response.status == 403:
                            last_error = f"Access denied: {response.status}"
                            logger.warning(
                                f"Got 403 on {url} (auth problem or private media)"
                            )
                        else:
                            last_error = f"HTTP {response.status}"
                        break

                except aiohttp.ClientError as e:
                    if attempt < self._MEDIA_HTTP_MAX_RETRIES:
                        delay = self._compute_retry_delay(attempt)
                        attempt += 1
                        logger.warning(
                            "Matrix media download network error, retrying in "
                            f"{delay:.2f}s ({attempt}/{self._MEDIA_HTTP_MAX_RETRIES}): {e}"
                        )
                        await asyncio.sleep(delay)
                        continue
                    last_error = str(e)
                    logger.debug(f"Network error downloading from {url}: {e}")
                    break
                except Exception as e:
                    last_error = str(e)
                    logger.debug(f"Exception downloading from {url}: {e}")
                    break

        # 所有端点都失败了，尝试缩略图作为最后手段
        if allow_thumbnail_fallback and last_status in [403, 404]:
            logger.debug("Trying thumbnail endpoints as fallback...")
            thumbnail_endpoints = [
                f"/_matrix/client/v1/media/thumbnail/{server_name}/{media_id}?width=800&height=600",
            ]

            for endpoint in thumbnail_endpoints:
                url = f"{self.homeserver}{endpoint}"
                headers = {"User-Agent": "AstrBot Matrix Client/1.0"}
                if self.access_token:
                    headers["Authorization"] = f"Bearer {self.access_token}"

                attempt = 0
                while True:
                    try:
                        async with self.session.get(
                            url, headers=headers, allow_redirects=True
                        ) as response:
                            if response.status == 200:
                                logger.info(
                                    "Downloaded thumbnail instead of full media"
                                )
                                if resolved_output_path is not None:
                                    await self._save_response_to_path(
                                        response, resolved_output_path
                                    )
                                    return None
                                return await response.read()

                            if (
                                self._should_retry_http_status(response.status)
                                and attempt < self._MEDIA_HTTP_MAX_RETRIES
                            ):
                                retry_after_seconds = self._extract_retry_after_seconds(
                                    response.headers, None
                                )
                                delay = self._compute_retry_delay(
                                    attempt, retry_after_seconds
                                )
                                attempt += 1
                                await asyncio.sleep(delay)
                                continue
                            break
                    except aiohttp.ClientError:
                        if attempt < self._MEDIA_HTTP_MAX_RETRIES:
                            delay = self._compute_retry_delay(attempt)
                            attempt += 1
                            await asyncio.sleep(delay)
                            continue
                        break
                    except Exception:
                        break

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
