"""Media download, decryption, and background-task primitives."""

import asyncio
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

from astrbot.api import logger

from ....utils.media_crypto import decrypt_encrypted_file


class MatrixReceiverMediaDownloadMixin:
    """Download plain or encrypted media into the receiver cache."""

    async def _run_download_task(
        self, task_key: str, task_factory: Callable[[], Awaitable[Path]]
    ) -> Path:
        existing_task = self._media_download_tasks.get(task_key)
        if existing_task:
            return await existing_task

        task = asyncio.create_task(task_factory())
        self._media_download_tasks[task_key] = task
        try:
            return await task
        finally:
            current_task = self._media_download_tasks.get(task_key)
            if current_task is task:
                self._media_download_tasks.pop(task_key, None)

    def _track_background_task(self, task: asyncio.Task, task_name: str) -> None:
        self._background_tasks.add(task)

        def _cleanup(done_task: asyncio.Task) -> None:
            self._background_tasks.discard(done_task)
            try:
                done_task.result()
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.debug(f"Background task failed ({task_name}): {e}")

        task.add_done_callback(_cleanup)

    async def _write_cache_file(self, cache_path: Path, data: bytes) -> None:
        def _write() -> None:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            temp_name = f".{cache_path.name}.{time.time_ns()}.tmp"
            temp_path = cache_path.with_name(temp_name)
            temp_path.write_bytes(data)
            temp_path.replace(cache_path)

        await asyncio.to_thread(_write)
        cache_key = self._extract_cache_key_from_path(cache_path)
        if cache_key:
            self._upsert_media_cache_index_entry(
                cache_key, cache_path, size_bytes=len(data)
            )

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
