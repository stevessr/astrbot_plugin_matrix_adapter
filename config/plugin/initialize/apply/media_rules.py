"""Plugin matrix_media_rules configuration extraction and normalization."""

from ....defaults import (
    _DEFAULT_MEDIA_UPLOAD_ALLOWED_MIME_RULES,
    _DEFAULT_MEDIA_UPLOAD_BLOCKED_EXTENSIONS,
    _normalize_bool,
    _normalize_token_list,
)


class PluginConfigInitializationMediaRulesMixin:
    """Apply matrix_media_rules settings from the config dictionary."""

    def _initialize_media_rules(self, config: dict) -> None:
        media_rules_obj = config.get("matrix_media_rules")

        media_upload_strict_mime_check = None
        media_upload_blocked_extensions = None
        media_upload_allowed_mime_rules = None
        if isinstance(media_rules_obj, dict):
            if isinstance(media_rules_obj.get("strict_mime_check"), (bool, str)):
                media_upload_strict_mime_check = media_rules_obj.get(
                    "strict_mime_check"
                )
            if isinstance(
                media_rules_obj.get("blocked_extensions"), (str, list, tuple, set)
            ):
                media_upload_blocked_extensions = media_rules_obj.get(
                    "blocked_extensions"
                )
            if isinstance(
                media_rules_obj.get("allowed_mime_rules"), (str, list, tuple, set)
            ):
                media_upload_allowed_mime_rules = media_rules_obj.get(
                    "allowed_mime_rules"
                )

        if media_upload_strict_mime_check is None:
            media_upload_strict_mime_check = config.get(
                "matrix_media_upload_strict_mime_check"
            )
        if media_upload_blocked_extensions is None:
            media_upload_blocked_extensions = config.get(
                "matrix_media_upload_blocked_extensions"
            )
        if media_upload_allowed_mime_rules is None:
            media_upload_allowed_mime_rules = config.get(
                "matrix_media_upload_allowed_mime_rules"
            )

        self._media_upload_strict_mime_check = _normalize_bool(
            media_upload_strict_mime_check, True
        )
        self._media_upload_blocked_extensions = _normalize_token_list(
            media_upload_blocked_extensions,
            _DEFAULT_MEDIA_UPLOAD_BLOCKED_EXTENSIONS,
            extension_mode=True,
            config_key="matrix_media_rules.blocked_extensions",
        )
        self._media_upload_allowed_mime_rules = _normalize_token_list(
            media_upload_allowed_mime_rules,
            _DEFAULT_MEDIA_UPLOAD_ALLOWED_MIME_RULES,
            config_key="matrix_media_rules.allowed_mime_rules",
        )
