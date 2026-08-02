"""Configurable MIME and extension upload policy helpers."""

from .compat import get_plugin_config


class MediaMimePolicyMixin:
    """Resolve blocked extensions and allowed MIME rules."""

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
