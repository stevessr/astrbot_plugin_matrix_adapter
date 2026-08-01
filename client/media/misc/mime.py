"""Media MIME normalization and upload security helpers."""

import mimetypes
from pathlib import Path

from ....config.plugin import get_plugin_config


class MediaMimeMixin:
    """Validate media uploads using extension, signature, and MIME policy."""

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
