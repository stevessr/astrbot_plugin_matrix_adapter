"""Derived Matrix configuration properties."""

from pathlib import Path

from ...auth.webhook import build_unified_webhook_url
from ...events.call import CallEventConfig
from ...storage.backend import StorageBackendConfig
from ..plugin import get_plugin_config


class MatrixConfigPropertiesMixin:
    """Expose typed configuration views used by runtime services."""

    @property
    def store_path(self) -> Path:
        return get_plugin_config().store_path

    @property
    def call_event_config(self) -> CallEventConfig:
        """Live 通话事件呈现配置。"""
        return CallEventConfig(
            enabled=self.enable_call_events,
            include_1to1=self.call_include_1to1,
            include_group=self.call_include_group,
            include_ringing=self.call_include_ringing,
            suppress_signalling=self.call_suppress_signalling,
        )

    @property
    def e2ee_store_path(self) -> Path:
        return get_plugin_config().e2ee_store_path

    @property
    def media_cache_dir(self) -> Path:
        return get_plugin_config().media_cache_dir

    @property
    def auth_callback_url(self) -> str:
        if not self.webhook_uuid:
            raise ValueError("webhook_uuid is required for Matrix auth callback")
        return build_unified_webhook_url(self.webhook_uuid)

    @property
    def storage_backend_config(self) -> StorageBackendConfig:
        return get_plugin_config().storage_backend_config

    @property
    def data_storage_backend(self) -> str:
        return get_plugin_config().data_storage_backend

    @property
    def pgsql_dsn(self) -> str:
        return get_plugin_config().pgsql_dsn

    @property
    def pgsql_schema(self) -> str:
        return get_plugin_config().pgsql_schema

    @property
    def pgsql_table_prefix(self) -> str:
        return get_plugin_config().pgsql_table_prefix
