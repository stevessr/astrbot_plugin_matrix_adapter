"""Matrix 消息接收组件 - 媒体下载 mixin"""

import asyncio
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

from astrbot.api import logger
from astrbot.api.event import MessageChain
from astrbot.api.message_components import File, Image, Record, Video

from ...constants import (
    MSGTYPE_AUDIO,
    MSGTYPE_FILE,
    MSGTYPE_IMAGE,
    MSGTYPE_STICKER,
    MSGTYPE_VIDEO,
)
from ...plugin_config import get_plugin_config
from ...utils.media_crypto import decrypt_encrypted_file


class MatrixReceiverMediaMixin:
    """MatrixReceiver 媒体下载 mixin"""

    def _should_auto_download_media(self, msgtype: str) -> bool:
        """检查是否应该自动下载该类型的媒体文件"""
        if msgtype not in {MSGTYPE_IMAGE, MSGTYPE_STICKER, MSGTYPE_VIDEO, MSGTYPE_AUDIO, MSGTYPE_FILE}:
            return False
        try:
            return get_plugin_config().is_media_auto_download_enabled(msgtype)
        except Exception:
            return True

    @staticmethod
    def _normalize_media_size(size_value) -> int | None:
        if isinstance(size_value, bool) or size_value is None:
            return None
        try:
            size = int(size_value)
        except (TypeError, ValueError):
            return None
        return size if size >= 0 else None

    def _extract_media_size(self, content: dict | None) -> int | None:
        if not isinstance(content, dict):
            return None
        info = content.get("info")
        if not isinstance(info, dict):
            return None
        return self._normalize_media_size(info.get("size"))

    def _get_media_auto_download_max_bytes(self) -> int:
        try:
            configured = int(get_plugin_config().media_auto_download_max_bytes)
        except Exception:
            return 0
        return max(0, configured)

    def _get_quoted_media_background_download_concurrency(self) -> int:
        try:
            configured = int(
                get_plugin_config().quoted_media_background_download_concurrency
            )
        except Exception:
            configured = self._QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY_DEFAULT
        if configured <= 0:
            configured = self._QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY_DEFAULT
        return min(configured, 32)

    def _is_media_over_auto_download_limit(self, size_bytes: int | None) -> bool:
        if size_bytes is None:
            return False
        max_bytes = self._get_media_auto_download_max_bytes()
        return max_bytes > 0 and size_bytes > max_bytes

    def _is_image_media(
        self, filename: str | None = None, mimetype: str | None = None
    ) -> bool:
        if mimetype:
            normalized = mimetype.lower().split(";")[0].strip()
            if normalized.startswith("image/"):
                return True
        if filename:
            return Path(filename).suffix.lower() in self._IMAGE_EXTENSIONS
        return False

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

    async def _append_quoted_media_component(
        self, chain: MessageChain, msgtype: str, content: dict
    ) -> bool:
        if not self._should_auto_download_media(msgtype):
            return False

        file_info = content.get("file")
        mxc_url = content.get("url")
        if not mxc_url and isinstance(file_info, dict):
            mxc_url = file_info.get("url")
        if not mxc_url:
            return False

        info = content.get("info", {})
        mimetype = info.get("mimetype") if isinstance(info, dict) else None
        size_bytes = self._extract_media_size(content)
        if self._is_media_over_auto_download_limit(size_bytes):
            if self.mxc_converter and not file_info:
                http_url = self.mxc_converter(mxc_url)
                if msgtype == MSGTYPE_IMAGE:
                    chain.chain.append(Image.fromURL(http_url))
                    return True
                if msgtype == MSGTYPE_VIDEO:
                    chain.chain.append(Video.fromURL(http_url))
                    return True
                if msgtype == MSGTYPE_AUDIO:
                    chain.chain.append(Record.fromURL(http_url))
                    return True
                if msgtype == MSGTYPE_FILE:
                    filename = content.get("filename") or content.get(
                        "body", "file.bin"
                    )
                    chain.chain.append(File(name=filename, url=http_url))
                    return True
            logger.debug(
                f"Quoted media over auto-download limit, skip local download: {msgtype}"
            )
            return False

        filename = content.get("filename")
        if not filename:
            default_name_map = {
                MSGTYPE_IMAGE: "image.jpg",
                MSGTYPE_VIDEO: "video.mp4",
                MSGTYPE_AUDIO: "audio.mp3",
                MSGTYPE_FILE: "file.bin",
            }
            filename = content.get("body", default_name_map.get(msgtype, "media.bin"))

        def _append_http_component(http_url: str) -> bool:
            if msgtype == MSGTYPE_IMAGE:
                chain.chain.append(Image.fromURL(http_url))
                return True
            if msgtype == MSGTYPE_VIDEO:
                chain.chain.append(Video.fromURL(http_url))
                return True
            if msgtype == MSGTYPE_AUDIO:
                chain.chain.append(Record.fromURL(http_url))
                return True
            if msgtype == MSGTYPE_FILE:
                chain.chain.append(File(name=filename, url=http_url))
                return True
            return False

        def _schedule_background_download() -> None:
            async def _background_download() -> None:
                async with self._quoted_media_background_download_semaphore:
                    if isinstance(file_info, dict):
                        await self._download_encrypted_media_file(
                            file_info, filename, mimetype
                        )
                    else:
                        await self._download_media_file(mxc_url, filename, mimetype)

            self._track_background_task(
                asyncio.create_task(_background_download()),
                f"quoted_media:{msgtype}",
            )

        try:
            if isinstance(file_info, dict):
                cache_path = await asyncio.wait_for(
                    self._download_encrypted_media_file(file_info, filename, mimetype),
                    timeout=self._QUOTED_MEDIA_DOWNLOAD_TIMEOUT_SECONDS,
                )
            else:
                cache_path = await asyncio.wait_for(
                    self._download_media_file(mxc_url, filename, mimetype),
                    timeout=self._QUOTED_MEDIA_DOWNLOAD_TIMEOUT_SECONDS,
                )
        except asyncio.TimeoutError:
            if self.mxc_converter and not isinstance(file_info, dict):
                http_url = self.mxc_converter(mxc_url)
                rendered = _append_http_component(http_url)
                if rendered:
                    _schedule_background_download()
                    logger.debug(
                        f"Quoted media download timed out, fallback to URL: {msgtype}"
                    )
                    return True
            logger.warning(f"Quoted media download timed out ({msgtype})")
            return False
        except Exception as e:
            logger.warning(f"Failed to download quoted media ({msgtype}): {e}")
            return False

        if msgtype == MSGTYPE_IMAGE:
            chain.chain.append(Image.fromFileSystem(str(cache_path)))
            return True
        if msgtype == MSGTYPE_VIDEO:
            chain.chain.append(Video.fromFileSystem(str(cache_path)))
            return True
        if msgtype == MSGTYPE_AUDIO:
            chain.chain.append(Record.fromFileSystem(str(cache_path)))
            return True
        if msgtype == MSGTYPE_FILE:
            chain.chain.append(File(name=filename, file=str(cache_path)))
            return True
        return False

    async def shutdown(self) -> None:
        tasks: list[asyncio.Task] = []
        seen: set[int] = set()

        for task in list(self._background_tasks):
            if task.done():
                continue
            marker = id(task)
            if marker not in seen:
                seen.add(marker)
                tasks.append(task)

        for task in list(self._media_download_tasks.values()):
            if task.done():
                continue
            marker = id(task)
            if marker not in seen:
                seen.add(marker)
                tasks.append(task)

        for task in tasks:
            task.cancel()

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        self._background_tasks.clear()
        self._media_download_tasks.clear()
