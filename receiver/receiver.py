"""
Matrix 消息接收组件
"""

import asyncio
import hashlib
import mimetypes
import string
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

from astrbot.api import logger
from astrbot.api.event import MessageChain
from astrbot.api.message_components import File, Image, Record, Video
from astrbot.api.platform import AstrBotMessage
from astrbot.core.platform.astrbot_message import MessageMember
from astrbot.core.platform.message_type import MessageType
from astrbot.core.utils import astrbot_path

# Update import: Client event types are in ..client.event_types
from ..client.event_types import MatrixRoom
from ..constants import REL_TYPE_THREAD
from ..plugin_config import get_plugin_config
from ..utils.media_cache_index import MediaCacheIndexStore
from ..utils.media_crypto import decrypt_encrypted_file
from ..utils.utils import MatrixUtils
from .handlers import (
    ROOM_STATE_HANDLERS,
    handle_audio,
    handle_file,
    handle_image,
    handle_location,
    handle_poll_end,
    handle_poll_response,
    handle_reaction,
    handle_redaction,
    handle_sticker,
    handle_text,
    handle_unknown,
    handle_video,
)


class MatrixReceiver:
    _REPLY_EVENT_FETCH_TIMEOUT_SECONDS = 2.0
    _QUOTED_MEDIA_DOWNLOAD_TIMEOUT_SECONDS = 2.5
    _IMAGE_EXTENSIONS = {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".bmp",
        ".svg",
        ".avif",
        ".heic",
        ".heif",
    }

    def __init__(
        self,
        user_id: str,
        mxc_converter: callable = None,
        bot_name: str = "MatrixBot",
        client=None,
    ):
        self.user_id = user_id
        self.mxc_converter = mxc_converter
        self.bot_name = bot_name
        self.client = client  # MatrixHTTPClient instance needed for downloading files
        self._media_download_tasks: dict[str, asyncio.Task[Path]] = {}
        self._background_tasks: set[asyncio.Task] = set()
        self._media_cache_index: dict[str, Path] = {}
        self._media_cache_index_store: MediaCacheIndexStore | None = None
        self._initialize_media_cache_index_store()

    def _get_media_cache_dir(self) -> Path:
        """获取媒体文件缓存目录"""
        try:
            cache_dir = Path(get_plugin_config().media_cache_dir)
        except Exception:
            cache_dir = (
                Path(astrbot_path.get_astrbot_data_path()) / "temp" / "matrix_media"
            )

        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir

    def _should_auto_download_media(self, msgtype: str) -> bool:
        """检查是否应该自动下载该类型的媒体文件"""
        if msgtype not in {"m.image", "m.sticker", "m.video", "m.audio", "m.file"}:
            return False
        try:
            return get_plugin_config().is_media_auto_download_enabled(msgtype)
        except Exception:
            return True

    @staticmethod
    def _media_cache_index_filename() -> str:
        return "media_cache_index.sqlite3"

    def _is_media_cache_index_persist_enabled(self) -> bool:
        try:
            return bool(get_plugin_config().media_cache_index_persist)
        except Exception:
            return True

    def _initialize_media_cache_index_store(self) -> None:
        if not self._is_media_cache_index_persist_enabled():
            return
        cache_dir = self._get_media_cache_dir()
        db_path = cache_dir / self._media_cache_index_filename()
        try:
            self._media_cache_index_store = MediaCacheIndexStore(
                db_path=db_path,
                cache_dir=cache_dir,
            )
            self._heal_media_cache_index()
        except Exception as e:
            logger.warning(f"Failed to initialize media cache index store: {e}")
            self._media_cache_index_store = None

    def _heal_media_cache_index(self) -> None:
        if not self._media_cache_index_store:
            return

        cache_dir = self._get_media_cache_dir()
        disk_entries: dict[str, Path] = {}
        disk_sizes: dict[str, int] = {}
        disk_mtime: dict[str, float] = {}

        try:
            for path in cache_dir.iterdir():
                if not path.is_file():
                    continue
                if self._media_cache_index_store.is_index_file(path):
                    continue
                cache_key = self._extract_cache_key_from_path(path)
                if not cache_key:
                    continue
                try:
                    stat_result = path.stat()
                except Exception:
                    continue
                if stat_result.st_size <= 0:
                    continue
                previous_mtime = disk_mtime.get(cache_key)
                if (
                    previous_mtime is not None
                    and previous_mtime >= stat_result.st_mtime
                ):
                    continue
                disk_entries[cache_key] = path
                disk_sizes[cache_key] = stat_result.st_size
                disk_mtime[cache_key] = stat_result.st_mtime
        except Exception as e:
            logger.debug(f"Failed to scan media cache directory for healing: {e}")
            return

        stale_removed = 0
        try:
            indexed_entries = self._media_cache_index_store.list_entries()
        except Exception as e:
            logger.debug(f"Failed to read media cache index entries for healing: {e}")
            indexed_entries = []

        for cache_key, _ in indexed_entries:
            if cache_key not in disk_entries:
                self._remove_media_cache_index_entry(cache_key)
                stale_removed += 1

        repaired = 0
        for cache_key, cache_path in disk_entries.items():
            self._upsert_media_cache_index_entry(
                cache_key,
                cache_path,
                size_bytes=disk_sizes.get(cache_key),
            )
            repaired += 1

        if stale_removed > 0 or repaired > 0:
            logger.debug(
                "Healed media cache index on startup: "
                f"indexed={repaired}, removed_stale={stale_removed}"
            )

    def _remove_media_cache_index_entry(
        self, cache_key: str | None, path: Path | None = None
    ) -> None:
        if cache_key:
            self._media_cache_index.pop(cache_key, None)
        if not self._media_cache_index_store:
            return
        try:
            if cache_key:
                self._media_cache_index_store.safe_remove(cache_key)
            elif path is not None:
                self._media_cache_index_store.remove_by_path(path)
        except Exception as e:
            logger.debug(f"Failed to remove media cache index entry: {e}")

    def _upsert_media_cache_index_entry(
        self, cache_key: str, cache_path: Path, *, size_bytes: int | None = None
    ) -> None:
        self._media_cache_index[cache_key] = cache_path
        if not self._media_cache_index_store:
            return
        try:
            self._media_cache_index_store.upsert(
                cache_key,
                cache_path,
                size_bytes=size_bytes,
            )
        except Exception as e:
            logger.debug(f"Failed to upsert media cache index entry: {e}")

    def _touch_cached_media_path(self, cache_key: str | None, cache_path: Path) -> None:
        try:
            cache_path.touch()
        except Exception:
            pass

        if cache_key is None:
            cache_key = self._extract_cache_key_from_path(cache_path)
        if cache_key is None:
            return

        try:
            size_bytes = cache_path.stat().st_size
        except Exception:
            size_bytes = None
        self._upsert_media_cache_index_entry(
            cache_key, cache_path, size_bytes=size_bytes
        )

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

    @staticmethod
    def _media_cache_key(mxc_url: str) -> str:
        return hashlib.md5(mxc_url.encode()).hexdigest()

    @staticmethod
    def _extract_cache_key_from_path(path: Path) -> str | None:
        name = path.name
        if len(name) < 32:
            return None
        candidate = name[:32].lower()
        if all(ch in string.hexdigits for ch in candidate):
            return candidate
        return None

    @staticmethod
    def _guess_media_ext(filename: str | None, mimetype: str | None) -> str:
        if filename:
            suffix = Path(filename).suffix
            if suffix:
                return suffix.lower()

        if mimetype:
            normalized_mimetype = mimetype.lower().split(";")[0].strip()
            ext_map = {
                "image/png": ".png",
                "image/jpeg": ".jpg",
                "image/gif": ".gif",
                "image/webp": ".webp",
                "video/mp4": ".mp4",
                "video/webm": ".webm",
                "video/quicktime": ".mov",
                "audio/mpeg": ".mp3",
                "audio/ogg": ".ogg",
                "audio/wav": ".wav",
                "audio/x-wav": ".wav",
            }
            mapped = ext_map.get(normalized_mimetype)
            if mapped:
                return mapped
            guessed = mimetypes.guess_extension(normalized_mimetype, strict=False)
            if guessed:
                return ".jpg" if guessed == ".jpe" else guessed

        return ".bin"

    def _find_existing_media_cache_file(
        self, cache_key: str, cache_dir: Path
    ) -> Path | None:
        cached = self._media_cache_index.get(cache_key)
        if cached:
            try:
                size_bytes = cached.stat().st_size
                if cached.is_file() and size_bytes > 0:
                    self._upsert_media_cache_index_entry(
                        cache_key, cached, size_bytes=size_bytes
                    )
                    return cached
            except Exception:
                pass
            self._remove_media_cache_index_entry(cache_key)

        if self._media_cache_index_store:
            try:
                indexed_path = self._media_cache_index_store.get(cache_key)
                if indexed_path and indexed_path.is_file():
                    size_bytes = indexed_path.stat().st_size
                    if size_bytes > 0:
                        self._upsert_media_cache_index_entry(
                            cache_key, indexed_path, size_bytes=size_bytes
                        )
                        return indexed_path
                if indexed_path:
                    self._remove_media_cache_index_entry(cache_key)
            except Exception as e:
                logger.debug(f"Failed to restore media cache index entry: {e}")

        try:
            for path in cache_dir.glob(f"{cache_key}*"):
                if path.is_file() and path.stat().st_size > 0:
                    self._upsert_media_cache_index_entry(
                        cache_key, path, size_bytes=path.stat().st_size
                    )
                    return path
        except Exception:
            return None
        return None

    def _build_media_cache_path(
        self, mxc_url: str, filename: str | None = None, mimetype: str | None = None
    ) -> Path:
        cache_key = self._media_cache_key(mxc_url)
        cache_dir = self._get_media_cache_dir()
        existing = self._find_existing_media_cache_file(cache_key, cache_dir)
        if existing:
            return existing

        ext = self._guess_media_ext(filename, mimetype)
        return cache_dir / f"{cache_key}{ext}"

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
                if msgtype == "m.image":
                    chain.chain.append(Image.fromURL(http_url))
                    return True
                if msgtype == "m.video":
                    chain.chain.append(Video.fromURL(http_url))
                    return True
                if msgtype == "m.audio":
                    chain.chain.append(Record.fromURL(http_url))
                    return True
                if msgtype == "m.file":
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
                "m.image": "image.jpg",
                "m.video": "video.mp4",
                "m.audio": "audio.mp3",
                "m.file": "file.bin",
            }
            filename = content.get("body", default_name_map.get(msgtype, "media.bin"))

        def _append_http_component(http_url: str) -> bool:
            if msgtype == "m.image":
                chain.chain.append(Image.fromURL(http_url))
                return True
            if msgtype == "m.video":
                chain.chain.append(Video.fromURL(http_url))
                return True
            if msgtype == "m.audio":
                chain.chain.append(Record.fromURL(http_url))
                return True
            if msgtype == "m.file":
                chain.chain.append(File(name=filename, url=http_url))
                return True
            return False

        def _schedule_background_download() -> None:
            async def _background_download() -> None:
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

        if msgtype == "m.image":
            chain.chain.append(Image.fromFileSystem(str(cache_path)))
            return True
        if msgtype == "m.video":
            chain.chain.append(Video.fromFileSystem(str(cache_path)))
            return True
        if msgtype == "m.audio":
            chain.chain.append(Record.fromFileSystem(str(cache_path)))
            return True
        if msgtype == "m.file":
            chain.chain.append(File(name=filename, file=str(cache_path)))
            return True
        return False

    def gc_media_cache(self, older_than_days: int | None = None) -> int:
        """清理媒体缓存，返回删除文件数"""
        cache_dir = self._get_media_cache_dir()
        if older_than_days is None:
            older_than_days = get_plugin_config().media_cache_gc_days

        if older_than_days <= 0:
            return 0

        cutoff = time.time() - older_than_days * 86400
        removed = 0

        for path in cache_dir.iterdir():
            if not path.is_file():
                continue
            if (
                self._media_cache_index_store
                and self._media_cache_index_store.is_index_file(path)
            ):
                continue
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
                    cache_key = self._extract_cache_key_from_path(path)
                    self._remove_media_cache_index_entry(cache_key, path=path)
            except Exception as e:
                logger.debug(f"清理媒体缓存失败：{path} ({e})")

        return removed

    async def convert_message(self, room: MatrixRoom, event) -> AstrBotMessage:
        """
        将 Matrix 消息转换为 AstrBot 消息格式
        """
        message = AstrBotMessage()

        # 基础信息
        message.raw_message = event

        # Strip reply fallback from body
        message.message_str = MatrixUtils.strip_reply_fallback(event.body)
        message.session_id = room.room_id
        message.message_id = event.event_id  # Set message ID for replies
        message.self_id = self.user_id  # Set bot's self ID

        # 根据房间成员数量判断是否为群聊
        # is_group 属性：member_count > 2 则为群聊，否则为私聊
        # 根据配置强制消息类型，默认为 auto（按房间成员判断）
        force_type = get_plugin_config().force_message_type
        is_auto_type = force_type in {"auto", "stalk"}
        is_private = force_type == "private" or (is_auto_type and not room.is_group)
        if is_private:
            message.type = MessageType.FRIEND_MESSAGE
            logger.debug(
                "消息类型：FRIEND_MESSAGE "
                f"(force_type={force_type}, is_group={room.is_group})"
            )
        else:
            message.type = MessageType.GROUP_MESSAGE
            # 设置 group 以支持白名单的 group_id 匹配
            from astrbot.core.platform.astrbot_message import Group

            message.group = Group(group_id=room.room_id)
            logger.debug(
                "消息类型：GROUP_MESSAGE "
                f"(force_type={force_type}, is_group={room.is_group})"
            )

        # 发送者信息
        sender_id = event.sender
        sender_name = room.members.get(sender_id, sender_id)

        message.sender = MessageMember(
            user_id=sender_id,
            nickname=sender_name,
        )

        # 构建消息链
        chain = MessageChain()

        # 处理回复
        relates_to = event.content.get("m.relates_to", {})
        reply_event_id = None

        # 1. 检查标准的 m.in_reply_to
        if "m.in_reply_to" in relates_to:
            reply_event_id = relates_to["m.in_reply_to"].get("event_id")

        # 2. 检查嘟文串 (Threading) 回复
        if not reply_event_id and relates_to.get("rel_type") == REL_TYPE_THREAD:
            # 在嘟文串中，如果没有显式的 m.in_reply_to，则视为回复根消息或上一条消息
            # 这里简化处理，如果 rel_type 是 m.thread，我们将其视为回复
            reply_event_id = relates_to.get("event_id")

        if reply_event_id:
            # 创建回复组件
            from astrbot.api.message_components import Reply

            # 注意：Reply 组件通常需要完整的消息对象，但这里我们只有 ID
            # AstrBot 的 Reply 组件结构可能需要适配
            reply_comp = Reply(id=reply_event_id)
            chain.chain.append(reply_comp)

            # 尝试获取引用消息中的图片
            if self.client:
                try:
                    original_event = await asyncio.wait_for(
                        self.client.get_event(room.room_id, reply_event_id),
                        timeout=self._REPLY_EVENT_FETCH_TIMEOUT_SECONDS,
                    )
                    if original_event:
                        original_content = original_event.get("content", {})
                        original_msgtype = original_content.get("msgtype")

                        if original_msgtype in {
                            "m.image",
                            "m.video",
                            "m.audio",
                            "m.file",
                        }:
                            rendered = await self._append_quoted_media_component(
                                chain, original_msgtype, original_content
                            )
                            if rendered:
                                logger.debug(
                                    f"Added quoted media to chain: msgtype={original_msgtype}"
                                )
                except asyncio.TimeoutError:
                    logger.debug(
                        f"Reply event fetch timed out: room={room.room_id} event={reply_event_id}"
                    )
                except Exception as e:
                    logger.debug(f"Could not fetch original event for reply: {e}")

        # 处理消息内容
        msgtype = event.content.get("msgtype")
        event_type = getattr(event, "event_type", None)
        handlers = {
            "m.text": handle_text,
            "m.notice": handle_text,
            "m.emote": handle_text,
            "m.image": handle_image,
            "m.redaction": handle_redaction,
            "m.sticker": handle_sticker,
            "m.video": handle_video,
            "m.audio": handle_audio,
            "m.file": handle_file,
            "m.reaction": handle_reaction,
            "m.location": handle_location,
        }

        # Handle poll events by event type rather than msgtype
        if event_type in ("m.poll.response", "org.matrix.msc3381.poll.response"):
            await handle_poll_response(self, chain, event, event_type)
        elif event_type in ("m.poll.end", "org.matrix.msc3381.poll.end"):
            await handle_poll_end(self, chain, event, event_type)
        else:
            handler = handlers.get(msgtype, handle_unknown)
            await handler(self, chain, event, msgtype)

        message.message = (
            chain.chain
        )  # AstrBotMessage 需要列表格式的消息链 (list[BaseMessageComponent])
        return message

    async def convert_system_event(self, room: MatrixRoom, event) -> AstrBotMessage:
        """
        将 Matrix 非消息事件转换为 AstrBot 消息格式（OtherMessage）
        """
        message = AstrBotMessage()
        message.raw_message = event
        message.session_id = room.room_id
        message.message_id = event.event_id
        message.self_id = self.user_id
        message.type = MessageType.OTHER_MESSAGE

        force_type = get_plugin_config().force_message_type
        if force_type == "group" or (force_type in {"auto", "stalk"} and room.is_group):
            from astrbot.core.platform.astrbot_message import Group

            message.group = Group(group_id=room.room_id)

        sender_id = getattr(event, "sender", None)
        sender_name = room.members.get(sender_id, sender_id) if sender_id else None
        message.sender = MessageMember(
            user_id=sender_id or "",
            nickname=sender_name,
        )

        # Build message chain for state events
        chain = MessageChain()
        event_type = getattr(event, "event_type", None)

        # Handle room state events with specific handlers
        if event_type and event_type in ROOM_STATE_HANDLERS:
            handler = ROOM_STATE_HANDLERS[event_type]
            await handler(self, chain, event, event_type)
            if chain.chain:
                first_comp = chain.chain[0]
                message.message_str = getattr(first_comp, "text", "")
            else:
                message.message_str = ""
        else:
            message.message_str = ""

        message.message = chain.chain if chain.chain else []
        return message
