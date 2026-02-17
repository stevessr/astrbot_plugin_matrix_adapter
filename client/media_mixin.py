"""
Matrix HTTP Client - Media Mixin
Provides file upload and download methods
"""

import asyncio
import hashlib
import mimetypes
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import aiohttp

from astrbot.api import logger

from ..constants import HTTP_ERROR_STATUS_400
from ..plugin_config import get_plugin_config


class MediaMixin:
    """Media-related methods for Matrix client"""

    _MEDIA_UPLOAD_CACHE_TTL_SECONDS = 15 * 60
    _MEDIA_UPLOAD_CACHE_MAX_ENTRIES = 256
    _MEDIA_HTTP_MAX_RETRIES = 3
    _MEDIA_RETRY_BASE_DELAY_SECONDS = 0.75
    _MEDIA_RETRY_MAX_DELAY_SECONDS = 10.0
    _MEDIA_UPLOAD_SNIFF_BYTES = 512
    _MEDIA_DOWNLOAD_CONCURRENCY_DEFAULT = 4
    _MEDIA_UPLOAD_DEFAULT_BLOCKED_EXTENSIONS = frozenset(
        {
            ".exe",
            ".dll",
            ".bat",
            ".cmd",
            ".sh",
            ".ps1",
            ".jar",
            ".msi",
            ".scr",
            ".com",
        }
    )
    _MEDIA_UPLOAD_DEFAULT_ALLOWED_MIME_RULES = (
        "image/*",
        "video/*",
        "audio/*",
        "text/*",
        "application/pdf",
        "application/json",
        "application/zip",
        "application/octet-stream",
    )
    _MEDIA_MIME_ALIASES = {
        "image/jpg": "image/jpeg",
        "audio/mp3": "audio/mpeg",
        "audio/x-wav": "audio/wav",
        "application/x-zip-compressed": "application/zip",
    }

    class _HashingFileReader:
        """File wrapper that updates SHA-256 while aiohttp reads upload body."""

        def __init__(self, file_handle):
            self._file_handle = file_handle
            self._hasher = hashlib.sha256()

        def read(self, size: int = -1):
            chunk = self._file_handle.read(size)
            if chunk:
                self._hasher.update(chunk)
            return chunk

        def hexdigest(self) -> str:
            return self._hasher.hexdigest()

        def __getattr__(self, name: str):
            return getattr(self._file_handle, name)

    def _ensure_media_upload_cache(self) -> None:
        if not hasattr(self, "_media_upload_cache"):
            self._media_upload_cache: dict[str, tuple[str, float]] = {}
        if not hasattr(self, "_media_upload_inflight"):
            self._media_upload_inflight: dict[str, asyncio.Task[dict[str, Any]]] = {}

    def _ensure_media_download_flow_control(self) -> None:
        if not hasattr(self, "_media_download_semaphores"):
            self._media_download_semaphores: dict[str, asyncio.Semaphore] = {}
        if not hasattr(self, "_media_download_semaphore_limits"):
            self._media_download_semaphore_limits: dict[str, int] = {}
        if not hasattr(self, "_media_download_rate_locks"):
            self._media_download_rate_locks: dict[str, asyncio.Lock] = {}
        if not hasattr(self, "_media_download_next_allowed_at"):
            self._media_download_next_allowed_at: dict[str, float] = {}
        if not hasattr(self, "_media_download_breaker_failures"):
            self._media_download_breaker_failures: dict[str, int] = {}
        if not hasattr(self, "_media_download_breaker_open_until"):
            self._media_download_breaker_open_until: dict[str, float] = {}
        if not hasattr(self, "_media_download_breaker_locks"):
            self._media_download_breaker_locks: dict[str, asyncio.Lock] = {}

    @staticmethod
    def _normalize_media_source_key(source_key: str | None) -> str:
        if isinstance(source_key, str):
            normalized = source_key.strip().lower()
            if normalized:
                return normalized
        return "__homeserver__"

    def _get_media_download_concurrency_limit(self) -> int:
        default_limit = self._MEDIA_DOWNLOAD_CONCURRENCY_DEFAULT
        try:
            configured_limit = int(get_plugin_config().media_download_concurrency)
        except Exception:
            return default_limit
        if configured_limit <= 0:
            return default_limit
        return min(configured_limit, 64)

    def _get_media_download_min_interval_seconds(self) -> float:
        try:
            interval_ms = int(get_plugin_config().media_download_min_interval_ms)
        except Exception:
            return 0.0
        if interval_ms <= 0:
            return 0.0
        return interval_ms / 1000.0

    def _get_media_download_breaker_fail_threshold(self) -> int:
        try:
            threshold = int(get_plugin_config().media_download_breaker_fail_threshold)
        except Exception:
            return 6
        return max(0, threshold)

    def _get_media_download_breaker_base_cooldown_seconds(self) -> float:
        try:
            cooldown_ms = int(get_plugin_config().media_download_breaker_cooldown_ms)
        except Exception:
            return 5.0
        if cooldown_ms <= 0:
            return 0.0
        return cooldown_ms / 1000.0

    def _get_media_download_breaker_max_cooldown_seconds(self) -> float:
        try:
            cooldown_ms = int(
                get_plugin_config().media_download_breaker_max_cooldown_ms
            )
        except Exception:
            return 120.0
        if cooldown_ms <= 0:
            return 0.0
        return cooldown_ms / 1000.0

    def _is_media_download_breaker_enabled(self) -> bool:
        if self._get_media_download_breaker_fail_threshold() <= 0:
            return False
        return self._get_media_download_breaker_base_cooldown_seconds() > 0

    @staticmethod
    def _is_media_download_breaker_failure_status(status: int) -> bool:
        return status == 429 or status >= 500

    async def _wait_media_download_breaker(self, source_key: str) -> None:
        if not self._is_media_download_breaker_enabled():
            return

        self._ensure_media_download_flow_control()
        normalized_source = self._normalize_media_source_key(source_key)
        lock = self._media_download_breaker_locks.setdefault(
            normalized_source, asyncio.Lock()
        )
        sleep_for = 0.0

        async with lock:
            open_until = self._media_download_breaker_open_until.get(
                normalized_source, 0.0
            )
            now = time.monotonic()
            if open_until > now:
                sleep_for = open_until - now

        if sleep_for > 0:
            logger.debug(
                "Matrix media download breaker open for "
                f"{normalized_source}, waiting {sleep_for:.2f}s"
            )
            await asyncio.sleep(sleep_for)

    def _record_media_download_success(self, source_key: str) -> None:
        self._ensure_media_download_flow_control()
        normalized_source = self._normalize_media_source_key(source_key)
        if self._media_download_breaker_failures.get(normalized_source, 0) > 0:
            self._media_download_breaker_failures[normalized_source] = 0
            self._media_download_breaker_open_until[normalized_source] = 0.0

    def _record_media_download_failure(
        self, source_key: str, status: int | None
    ) -> None:
        if not self._is_media_download_breaker_enabled():
            return
        self._ensure_media_download_flow_control()

        normalized_source = self._normalize_media_source_key(source_key)
        failure_count = (
            self._media_download_breaker_failures.get(normalized_source, 0) + 1
        )
        self._media_download_breaker_failures[normalized_source] = failure_count

        threshold = self._get_media_download_breaker_fail_threshold()
        if failure_count < threshold:
            return

        base_cooldown = self._get_media_download_breaker_base_cooldown_seconds()
        max_cooldown = self._get_media_download_breaker_max_cooldown_seconds()
        if max_cooldown <= 0:
            max_cooldown = base_cooldown
        if max_cooldown <= 0:
            return

        backoff_level = failure_count - threshold
        cooldown_seconds = min(base_cooldown * (2**backoff_level), max_cooldown)
        now = time.monotonic()
        new_open_until = now + cooldown_seconds
        current_open_until = self._media_download_breaker_open_until.get(
            normalized_source, 0.0
        )
        if new_open_until > current_open_until:
            self._media_download_breaker_open_until[normalized_source] = new_open_until

        logger.debug(
            "Opened Matrix media download breaker for "
            f"{normalized_source}: failures={failure_count}, "
            f"status={status}, cooldown={cooldown_seconds:.2f}s"
        )

    def _get_media_download_semaphore(self, source_key: str) -> asyncio.Semaphore:
        self._ensure_media_download_flow_control()
        normalized_source = self._normalize_media_source_key(source_key)
        limit = self._get_media_download_concurrency_limit()
        existing = self._media_download_semaphores.get(normalized_source)
        existing_limit = self._media_download_semaphore_limits.get(normalized_source)
        if existing is None or existing_limit != limit:
            existing = asyncio.Semaphore(limit)
            self._media_download_semaphores[normalized_source] = existing
            self._media_download_semaphore_limits[normalized_source] = limit
        return existing

    async def _apply_media_download_rate_limit(self, source_key: str) -> None:
        interval_seconds = self._get_media_download_min_interval_seconds()
        if interval_seconds <= 0:
            return

        self._ensure_media_download_flow_control()
        normalized_source = self._normalize_media_source_key(source_key)
        lock = self._media_download_rate_locks.setdefault(
            normalized_source, asyncio.Lock()
        )
        loop = asyncio.get_running_loop()
        async with lock:
            now = loop.time()
            next_allowed = self._media_download_next_allowed_at.get(
                normalized_source, now
            )
            if next_allowed > now:
                await asyncio.sleep(next_allowed - now)
                now = loop.time()
            self._media_download_next_allowed_at[normalized_source] = (
                now + interval_seconds
            )

    @asynccontextmanager
    async def _media_download_slot(self, source_key: str):
        semaphore = self._get_media_download_semaphore(source_key)
        await semaphore.acquire()
        try:
            await self._apply_media_download_rate_limit(source_key)
            yield
        finally:
            semaphore.release()

    @classmethod
    def _normalize_mime_type(cls, content_type: str | None) -> str:
        if not isinstance(content_type, str):
            return "application/octet-stream"
        normalized = content_type.lower().split(";", 1)[0].strip()
        if not normalized:
            return "application/octet-stream"
        return cls._MEDIA_MIME_ALIASES.get(normalized, normalized)

    @staticmethod
    def _normalize_extension(filename: str | None) -> str:
        if not isinstance(filename, str):
            return ""
        suffix = Path(filename).suffix.lower()
        return suffix.strip()

    def _is_media_upload_strict_mime_check_enabled(self) -> bool:
        try:
            return bool(get_plugin_config().media_upload_strict_mime_check)
        except Exception:
            return True

    def _get_media_upload_blocked_extensions(self) -> set[str]:
        try:
            configured = get_plugin_config().media_upload_blocked_extensions
        except Exception:
            configured = ()
        blocked = {
            ext.strip().lower()
            for ext in configured
            if isinstance(ext, str) and ext.strip()
        }
        if not blocked:
            blocked = set(self._MEDIA_UPLOAD_DEFAULT_BLOCKED_EXTENSIONS)
        return blocked

    def _get_media_upload_allowed_mime_rules(self) -> tuple[str, ...]:
        try:
            configured = get_plugin_config().media_upload_allowed_mime_rules
        except Exception:
            configured = ()
        normalized_rules = tuple(
            rule.strip().lower()
            for rule in configured
            if isinstance(rule, str) and rule.strip()
        )
        if normalized_rules:
            return normalized_rules
        return self._MEDIA_UPLOAD_DEFAULT_ALLOWED_MIME_RULES

    @staticmethod
    def _mime_allowed_by_rules(mime_type: str, rules: tuple[str, ...]) -> bool:
        for rule in rules:
            if rule.endswith("/*"):
                prefix = rule[:-1]
                if mime_type.startswith(prefix):
                    return True
                continue
            if mime_type == rule:
                return True
        return False

    @classmethod
    def _is_mime_compatible(cls, left: str, right: str) -> bool:
        normalized_left = cls._normalize_mime_type(left)
        normalized_right = cls._normalize_mime_type(right)
        if normalized_left == normalized_right:
            return True
        if (
            normalized_left == "application/octet-stream"
            or normalized_right == "application/octet-stream"
        ):
            return True
        left_major = normalized_left.split("/", 1)[0]
        right_major = normalized_right.split("/", 1)[0]
        if left_major == right_major and left_major in {
            "image",
            "audio",
            "video",
            "text",
        }:
            return True
        return False

    @staticmethod
    def _sniff_mime_from_bytes(data: bytes) -> str | None:
        if not data:
            return None

        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if data.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        if data.startswith((b"GIF87a", b"GIF89a")):
            return "image/gif"
        if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            return "image/webp"
        if data.startswith(b"BM"):
            return "image/bmp"
        if data.startswith((b"II*\x00", b"MM\x00*")):
            return "image/tiff"
        if data.startswith(b"%PDF-"):
            return "application/pdf"
        if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            return "application/zip"
        if data.startswith((b"\x1f\x8b\x08",)):
            return "application/gzip"
        if data.startswith(b"OggS"):
            return "audio/ogg"
        if data.startswith(b"fLaC"):
            return "audio/flac"
        if data.startswith(b"ID3"):
            return "audio/mpeg"
        if len(data) > 2 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0:
            return "audio/mpeg"
        if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
            return "audio/wav"
        if data[:4] == b"RIFF" and data[8:11] == b"AVI":
            return "video/x-msvideo"
        if len(data) >= 12 and data[4:8] == b"ftyp":
            return "video/mp4"
        if data.startswith(b"\x1a\x45\xdf\xa3"):
            return "video/webm"

        stripped = data.lstrip()
        if stripped.startswith((b"{", b"[")):
            return "application/json"
        if stripped:
            text_sample = stripped[:200]
            printable = sum(
                1 for b in text_sample if b in (9, 10, 13) or 32 <= b <= 126
            )
            if printable / max(1, len(text_sample)) >= 0.95:
                return "text/plain"
        return None

    @staticmethod
    def _read_file_head(path: Path, size: int) -> bytes:
        with path.open("rb") as f:
            return f.read(size)

    def _validate_media_upload_security(
        self,
        *,
        filename: str,
        declared_content_type: str,
        file_head: bytes,
    ) -> str:
        normalized_declared = self._normalize_mime_type(declared_content_type)
        extension = self._normalize_extension(filename)
        blocked_extensions = self._get_media_upload_blocked_extensions()
        if extension and (extension in blocked_extensions or "*" in blocked_extensions):
            raise ValueError(
                f"Blocked media upload extension: {extension} (file: {filename})"
            )

        allowed_rules = self._get_media_upload_allowed_mime_rules()
        if not self._mime_allowed_by_rules(normalized_declared, allowed_rules):
            raise ValueError(
                f"Declared MIME type is not allowed: {normalized_declared} (file: {filename})"
            )

        sniffed_mime = self._sniff_mime_from_bytes(file_head)
        extension_mime = self._normalize_mime_type(mimetypes.guess_type(filename)[0])
        strict_check = self._is_media_upload_strict_mime_check_enabled()

        if sniffed_mime and not self._mime_allowed_by_rules(
            sniffed_mime, allowed_rules
        ):
            raise ValueError(
                f"Sniffed MIME type is not allowed: {sniffed_mime} (file: {filename})"
            )

        if strict_check:
            if sniffed_mime and not self._is_mime_compatible(
                normalized_declared, sniffed_mime
            ):
                raise ValueError(
                    "Declared MIME does not match file signature: "
                    f"{normalized_declared} vs {sniffed_mime} (file: {filename})"
                )
            if (
                extension
                and extension_mime
                and not self._is_mime_compatible(normalized_declared, extension_mime)
            ):
                raise ValueError(
                    "Declared MIME does not match file extension: "
                    f"{normalized_declared} vs {extension_mime} (file: {filename})"
                )
            if (
                extension
                and extension_mime
                and sniffed_mime
                and not self._is_mime_compatible(extension_mime, sniffed_mime)
            ):
                raise ValueError(
                    "File extension does not match file signature: "
                    f"{extension_mime} vs {sniffed_mime} (file: {filename})"
                )

        if (
            normalized_declared == "application/octet-stream"
            and sniffed_mime
            and self._mime_allowed_by_rules(sniffed_mime, allowed_rules)
        ):
            return sniffed_mime
        if (
            normalized_declared == "application/octet-stream"
            and extension_mime
            and self._mime_allowed_by_rules(extension_mime, allowed_rules)
        ):
            return extension_mime
        return normalized_declared

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
    def _build_media_upload_cache_key_from_file_state(
        file_path: Path,
        content_type: str,
    ) -> str:
        stat_result = file_path.stat()
        identity = (
            f"{file_path.resolve()}:{stat_result.st_dev}:{stat_result.st_ino}:"
            f"{stat_result.st_size}:{stat_result.st_mtime_ns}"
        )
        digest = hashlib.sha256(identity.encode("utf-8", errors="ignore")).hexdigest()
        return f"{content_type}:path:{digest}"

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

        safe_content_type = self._validate_media_upload_security(
            filename=filename,
            declared_content_type=content_type,
            file_head=data[: self._MEDIA_UPLOAD_SNIFF_BYTES],
        )

        cache_key = self._build_media_upload_cache_key(data, safe_content_type)
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
                "Content-Type": safe_content_type,
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

        upload_filename = filename or path.name
        file_head = await asyncio.to_thread(
            self._read_file_head, path, self._MEDIA_UPLOAD_SNIFF_BYTES
        )
        safe_content_type = self._validate_media_upload_security(
            filename=upload_filename,
            declared_content_type=content_type,
            file_head=file_head,
        )

        path_cache_key = await asyncio.to_thread(
            self._build_media_upload_cache_key_from_file_state,
            path,
            safe_content_type,
        )
        cached_response = self._get_cached_upload_result(path_cache_key)
        if cached_response:
            return cached_response

        existing_task = self._media_upload_inflight.get(path_cache_key)
        if existing_task:
            logger.debug("Joining in-flight Matrix media upload task")
            return await existing_task

        async def _perform_upload_from_path() -> dict[str, Any]:
            url = f"{self.homeserver}/_matrix/media/v3/upload"
            headers = {
                "Content-Type": safe_content_type,
                "Authorization": f"Bearer {self.access_token}",
                "User-Agent": "AstrBot Matrix Client/1.0",
            }
            params = {"filename": upload_filename}
            attempt = 0

            while True:
                try:
                    with path.open("rb") as file_handle:
                        hashing_reader = self._HashingFileReader(file_handle)
                        async with self.session.post(
                            url,
                            data=hashing_reader,
                            headers=headers,
                            params=params,
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

                            digest_cache_key = (
                                self._build_media_upload_cache_key_from_digest(
                                    hashing_reader.hexdigest(),
                                    safe_content_type,
                                )
                            )
                            self._save_upload_cache_result(path_cache_key, content_uri)
                            self._save_upload_cache_result(
                                digest_cache_key, content_uri
                            )
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
        self._media_upload_inflight[path_cache_key] = upload_task
        try:
            return await upload_task
        finally:
            current_task = self._media_upload_inflight.get(path_cache_key)
            if current_task is upload_task:
                self._media_upload_inflight.pop(path_cache_key, None)

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

        if not mxc_url.startswith("mxc://"):
            raise ValueError(f"Invalid MXC URL: {mxc_url}")

        parts = mxc_url[6:].split("/", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid MXC URL format: {mxc_url}")

        server_name, media_id = parts
        source_key = self._normalize_media_source_key(server_name)

        proxy_endpoints = [
            f"/_matrix/client/v1/media/download/{server_name}/{media_id}",
        ]
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
                    await self._wait_media_download_breaker(source_key)
                    async with self._media_download_slot(source_key):
                        async with self.session.get(
                            url, headers=headers, allow_redirects=True
                        ) as response:
                            last_status = response.status
                            if response.status == 200:
                                self._record_media_download_success(source_key)
                                logger.debug(
                                    f"Successfully downloaded media from {url}"
                                )
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
                                logger.debug(
                                    "Matrix media download failed with status "
                                    f"{response.status}, retrying in {delay:.2f}s "
                                    f"({attempt}/{self._MEDIA_HTTP_MAX_RETRIES})"
                                )
                                await asyncio.sleep(delay)
                                continue

                            if self._is_media_download_breaker_failure_status(
                                response.status
                            ):
                                self._record_media_download_failure(
                                    source_key, response.status
                                )
                            if response.status == 404:
                                last_error = f"Media not found: {response.status}"
                            elif response.status == 403:
                                last_error = f"Access denied: {response.status}"
                                logger.debug(
                                    f"Got 403 on {url} (auth problem or private media)"
                                )
                            else:
                                last_error = f"HTTP {response.status}"
                            break

                except aiohttp.ClientError as e:
                    if attempt < self._MEDIA_HTTP_MAX_RETRIES:
                        delay = self._compute_retry_delay(attempt)
                        attempt += 1
                        logger.debug(
                            "Matrix media download network error, retrying in "
                            f"{delay:.2f}s ({attempt}/{self._MEDIA_HTTP_MAX_RETRIES}): {e}"
                        )
                        await asyncio.sleep(delay)
                        continue
                    self._record_media_download_failure(source_key, None)
                    last_error = str(e)
                    logger.debug(f"Network error downloading from {url}: {e}")
                    break
                except Exception as e:
                    last_error = str(e)
                    logger.debug(f"Exception downloading from {url}: {e}")
                    break

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
                        await self._wait_media_download_breaker(source_key)
                        async with self._media_download_slot(source_key):
                            async with self.session.get(
                                url, headers=headers, allow_redirects=True
                            ) as response:
                                if response.status == 200:
                                    self._record_media_download_success(source_key)
                                    logger.debug(
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
                                    retry_after_seconds = (
                                        self._extract_retry_after_seconds(
                                            response.headers, None
                                        )
                                    )
                                    delay = self._compute_retry_delay(
                                        attempt, retry_after_seconds
                                    )
                                    attempt += 1
                                    await asyncio.sleep(delay)
                                    continue
                                if self._is_media_download_breaker_failure_status(
                                    response.status
                                ):
                                    self._record_media_download_failure(
                                        source_key, response.status
                                    )
                                break
                    except aiohttp.ClientError:
                        if attempt < self._MEDIA_HTTP_MAX_RETRIES:
                            delay = self._compute_retry_delay(attempt)
                            attempt += 1
                            await asyncio.sleep(delay)
                            continue
                        self._record_media_download_failure(source_key, None)
                        break
                    except Exception:
                        break

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
        source_key = self._normalize_media_source_key(server_name)
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
                await self._wait_media_download_breaker(source_key)
                async with self._media_download_slot(source_key):
                    async with self.session.get(
                        url, headers=headers, allow_redirects=True
                    ) as response:
                        last_status = response.status
                        if response.status == 200:
                            self._record_media_download_success(source_key)
                            return await response.read()
                        if self._is_media_download_breaker_failure_status(
                            response.status
                        ):
                            self._record_media_download_failure(
                                source_key, response.status
                            )
                        last_error = f"HTTP {response.status}"
            except aiohttp.ClientError as e:
                self._record_media_download_failure(source_key, None)
                last_error = str(e)
                continue
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
