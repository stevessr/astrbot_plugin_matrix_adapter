"""
Matrix HTTP Client - Media Misc Mixin
Provides shared media helper methods
"""

import hashlib
import io
import mimetypes
from pathlib import Path
from typing import Any

from astrbot.api import logger

from ...plugin_config import get_plugin_config


class MediaMiscMixin:
    """Media helper methods for Matrix client"""

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

    class _HashingFileReader(io.IOBase):
        """IOBase-compatible file wrapper that hashes uploaded bytes."""

        def __init__(self, file_handle: io.BufferedReader):
            self._file_handle = file_handle
            self._hasher = hashlib.sha256()

        def read(self, size: int = -1) -> bytes:
            chunk = self._file_handle.read(size)
            if chunk:
                self._hasher.update(chunk)
            return chunk

        def readinto(self, b) -> int:
            reader = getattr(self._file_handle, "readinto", None)
            if callable(reader):
                n = reader(b)
                if n and n > 0:
                    self._hasher.update(memoryview(b)[:n])
                return n

            chunk = self._file_handle.read(len(b))
            if not chunk:
                return 0
            n = len(chunk)
            b[:n] = chunk
            self._hasher.update(chunk)
            return n

        def readline(self, size: int = -1) -> bytes:
            chunk = self._file_handle.readline(size)
            if chunk:
                self._hasher.update(chunk)
            return chunk

        def readable(self) -> bool:
            return True

        def seekable(self) -> bool:
            return self._file_handle.seekable()

        def writable(self) -> bool:
            return False

        def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
            return self._file_handle.seek(offset, whence)

        def tell(self) -> int:
            return self._file_handle.tell()

        def fileno(self) -> int:
            return self._file_handle.fileno()

        @property
        def closed(self) -> bool:
            return self._file_handle.closed

        def close(self) -> None:
            self._file_handle.close()

        def hexdigest(self) -> str:
            return self._hasher.hexdigest()

        def __getattr__(self, name: str):
            return getattr(self._file_handle, name)

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
            # ISO BMFF family (MP4/HEIF/AVIF/etc.)
            # bytes[8:12] is major brand, then minor version, then compatible brands.
            # We scan early brand slots to avoid misclassifying AVIF as generic MP4.
            brand_bytes = [data[i : i + 4] for i in range(8, min(len(data), 64) - 3, 4)]
            if any(brand in {b"avif", b"avis"} for brand in brand_bytes):
                return "image/avif"
            if any(
                brand in {b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"}
                for brand in brand_bytes
            ):
                return "image/heif"
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
