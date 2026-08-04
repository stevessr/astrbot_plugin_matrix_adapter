"""Plain (unencrypted) media download into the receiver cache."""

from pathlib import Path

from astrbot.api import logger


class MatrixReceiverMediaPlainDownloadMixin:
    """Download a plain MXC media URL into the receiver cache."""

    async def _download_media_file(
        self, mxc_url: str, filename: str = None, mimetype: str = None
    ) -> Path:
        """下载媒体文件并返回缓存路径"""
        if not self.client:
            raise Exception("No client available for downloading media")

        cache_path = self._build_media_cache_path(mxc_url, filename, mimetype)

        # 检查缓存
        if cache_path.exists() and cache_path.stat().st_size > 0:
            logger.debug(f"Using cached media file: {cache_path}")
            self._touch_cached_media_path(
                self._extract_cache_key_from_path(cache_path), cache_path
            )
            return cache_path

        async def _download() -> Path:
            resolved_cache_path = self._build_media_cache_path(
                mxc_url, filename, mimetype
            )
            if resolved_cache_path.exists() and resolved_cache_path.stat().st_size > 0:
                self._touch_cached_media_path(
                    self._extract_cache_key_from_path(resolved_cache_path),
                    resolved_cache_path,
                )
                return resolved_cache_path

            logger.debug(f"Downloading media file: {mxc_url}")
            download_result = await self.client.download_file(
                mxc_url,
                allow_thumbnail_fallback=self._is_image_media(filename, mimetype),
                output_path=resolved_cache_path,
            )
            if isinstance(download_result, (bytes, bytearray)):
                await self._write_cache_file(
                    resolved_cache_path, bytes(download_result)
                )
            else:
                cache_key = self._extract_cache_key_from_path(resolved_cache_path)
                if cache_key and resolved_cache_path.exists():
                    try:
                        size_bytes = resolved_cache_path.stat().st_size
                    except Exception:
                        size_bytes = None
                    self._upsert_media_cache_index_entry(
                        cache_key,
                        resolved_cache_path,
                        size_bytes=size_bytes,
                    )
            logger.debug(f"Saved media file to cache: {resolved_cache_path}")
            return resolved_cache_path

        try:
            return await self._run_download_task(f"plain:{mxc_url}", _download)
        except Exception as e:
            logger.error(f"Failed to download media file {mxc_url}: {e}")
            raise
