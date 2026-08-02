"""MIME normalization and compatibility matching helpers."""

from pathlib import Path


class MediaMimeNormalizationMixin:
    """Normalize MIME types, extensions, and policy rules."""

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
