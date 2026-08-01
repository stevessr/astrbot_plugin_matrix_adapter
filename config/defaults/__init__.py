"""Composable plugin configuration defaults and normalization helpers."""

from .normalize import (
    _normalize_bool,
    _normalize_message_type,
    _normalize_non_negative_int,
    _normalize_pgsql_schema,
    _normalize_pgsql_table_prefix,
    _normalize_token_list,
    _warn_config_coercion,
)
from .properties import PluginConfigDefaultsMixin
from .values import (
    _DEFAULT_E2EE_STORE_MAX_PENDING_WRITES,
    _DEFAULT_HTTP_TIMEOUT_SECONDS,
    _DEFAULT_MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES,
    _DEFAULT_MEDIA_UPLOAD_ALLOWED_MIME_RULES,
    _DEFAULT_MEDIA_UPLOAD_BLOCKED_EXTENSIONS,
    _DEFAULT_QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY,
    _get_default_data_dir,
)

__all__ = [
    "PluginConfigDefaultsMixin",
    "_DEFAULT_E2EE_STORE_MAX_PENDING_WRITES",
    "_DEFAULT_HTTP_TIMEOUT_SECONDS",
    "_DEFAULT_MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES",
    "_DEFAULT_MEDIA_UPLOAD_ALLOWED_MIME_RULES",
    "_DEFAULT_MEDIA_UPLOAD_BLOCKED_EXTENSIONS",
    "_DEFAULT_QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY",
    "_get_default_data_dir",
    "_normalize_bool",
    "_normalize_message_type",
    "_normalize_non_negative_int",
    "_normalize_pgsql_schema",
    "_normalize_pgsql_table_prefix",
    "_normalize_token_list",
    "_warn_config_coercion",
]
