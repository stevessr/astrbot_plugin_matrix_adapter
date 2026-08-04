"""Encrypted (E2EE attachment) media download and decryption."""

import asyncio
from pathlib import Path

from astrbot.api import logger

from .....utils.media_crypto import decrypt_encrypted_file


class MatrixReceiverMediaEncryptedDownloadMixin:
    """Download an encrypted MXC media file and decrypt it into the cache."""

    async def _download_encrypted_media_file(
        self, file_info: dict, filename: str | None = None, mimetype: str | None = None
    ) -> Path:
        """下载并解密媒体文件（E2EE 附件）"""
        if not self.client:
            raise Exception("No client available for downloading media")

        mxc_url = file_info.get("url")
        if not mxc_url:
            raise Exception("Encrypted media missing mxc url")

        cache_path = self._build_media_cache_path(mxc_url, filename, mimetype)
        if cache_path.exists() and cache_path.stat().st_size > 0:
            logger.debug(f"Using cached encrypted media file: {cache_path}")
            self._touch_cached_media_path(
                self._extract_cache_key_from_path(cache_path), cache_path
            )
            return cache_path

        key_info = file_info.get("key") or {}
        iv = file_info.get("iv") or ""
        sha256_hash = (file_info.get("hashes") or {}).get("sha256", "")
        encrypted_task_key = f"enc:{mxc_url}:{key_info.get('k', '')}:{iv}:{sha256_hash}"

        async def _download_and_decrypt() -> Path:
            resolved_cache_path = self._build_media_cache_path(
                mxc_url, filename, mimetype
            )
            if resolved_cache_path.exists() and resolved_cache_path.stat().st_size > 0:
                self._touch_cached_media_path(
                    self._extract_cache_key_from_path(resolved_cache_path),
                    resolved_cache_path,
                )
                return resolved_cache_path

            logger.debug(f"Downloading encrypted media file: {mxc_url}")
            ciphertext = await self.client.download_file(
                mxc_url,
                allow_thumbnail_fallback=False,
            )
            plaintext = await asyncio.to_thread(
                decrypt_encrypted_file, file_info, ciphertext
            )
            await self._write_cache_file(resolved_cache_path, plaintext)
            logger.debug(f"Saved decrypted media file to cache: {resolved_cache_path}")
            return resolved_cache_path

        return await self._run_download_task(encrypted_task_key, _download_and_decrypt)
