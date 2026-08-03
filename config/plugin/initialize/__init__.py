"""Composable plugin configuration initialization operations."""

from ....storage.backend import StorageBackendConfig, normalize_storage_backend
from ...defaults import (
    _DEFAULT_E2EE_STORE_MAX_PENDING_WRITES,
    _DEFAULT_HTTP_TIMEOUT_SECONDS,
    _DEFAULT_MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES,
    _DEFAULT_MEDIA_UPLOAD_ALLOWED_MIME_RULES,
    _DEFAULT_MEDIA_UPLOAD_BLOCKED_EXTENSIONS,
    _DEFAULT_QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY,
    _get_default_data_dir,
    _normalize_bool,
    _normalize_message_type,
    _normalize_non_negative_int,
    _normalize_pgsql_schema,
    _normalize_pgsql_table_prefix,
    _normalize_token_list,
    _warn_config_coercion,
)
from .apply import PluginConfigInitializationOperationsMixin


class PluginConfigInitializationMixin(PluginConfigInitializationOperationsMixin):
    """Apply external configuration values to a PluginConfig instance."""

    pass


# Preserve direct method attributes exposed by the former mixin.
PluginConfigInitializationMixin.initialize = (
    PluginConfigInitializationOperationsMixin.__dict__["initialize"]
)


__all__ = [
    "StorageBackendConfig",
    "PluginConfigInitializationMixin",
    "PluginConfigInitializationOperationsMixin",
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
    "normalize_storage_backend",
]
