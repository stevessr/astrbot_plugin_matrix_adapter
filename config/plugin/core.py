"""Plugin configuration singleton state and defaults."""

from pathlib import Path

from ...storage.backend import StorageBackendConfig
from ..defaults import (
    _DEFAULT_E2EE_STORE_MAX_PENDING_WRITES,
    _DEFAULT_HTTP_TIMEOUT_SECONDS,
    _DEFAULT_MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES,
    _DEFAULT_MEDIA_UPLOAD_ALLOWED_MIME_RULES,
    _DEFAULT_MEDIA_UPLOAD_BLOCKED_EXTENSIONS,
    _DEFAULT_QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY,
    PluginConfigDefaultsMixin,
    _get_default_data_dir,
)
from .initialize import PluginConfigInitializationMixin


class PluginConfig(
    PluginConfigInitializationMixin,
    PluginConfigDefaultsMixin,
):
    """Singleton storing plugin-level configuration state."""

    _instance: "PluginConfig | None" = None
    _initialized: bool = False
    _data_dir: Path | None = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if PluginConfig._initialized:
            return
        PluginConfig._initialized = True

        # 初始化默认值
        self._data_dir = _get_default_data_dir()
        self._store_path: Path = self._data_dir / "store"
        self._e2ee_store_path: Path = self._data_dir / "e2ee"
        self._media_cache_dir: Path = self._data_dir / "media"
        self._media_cache_gc_days: int = 30
        self._http_timeout_seconds: int = _DEFAULT_HTTP_TIMEOUT_SECONDS
        self._media_download_concurrency: int = 4
        self._quoted_media_background_download_concurrency: int = (
            _DEFAULT_QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY
        )
        self._media_download_min_interval_ms: int = 0
        self._media_download_breaker_fail_threshold: int = 6
        self._media_download_breaker_cooldown_ms: int = 5000
        self._media_download_breaker_max_cooldown_ms: int = 120000
        self._media_download_max_in_memory_bytes: int = (
            _DEFAULT_MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES
        )
        self._media_cache_index_persist: bool = True
        self._media_auto_download_max_bytes: int = 0
        self._media_auto_download_image: bool = True
        self._media_auto_download_video: bool = True
        self._media_auto_download_audio: bool = True
        self._media_auto_download_file: bool = True
        self._media_auto_download_sticker: bool = True
        self._media_upload_strict_mime_check: bool = True
        self._media_upload_blocked_extensions: tuple[str, ...] = (
            _DEFAULT_MEDIA_UPLOAD_BLOCKED_EXTENSIONS
        )
        self._media_upload_allowed_mime_rules: tuple[str, ...] = (
            _DEFAULT_MEDIA_UPLOAD_ALLOWED_MIME_RULES
        )
        # 消息类型配置
        self._force_message_type: str = "auto"
        # 回复自适应：入站消息位于消息列（Thread）内时，回复也留在同一消息列
        self._adaptive_thread_reply: bool = True
        # 是否发送「正在输入」状态与已读回执
        self._send_typing: bool = False
        self._send_read_receipt: bool = True
        # 数据存储后端（users/rooms/auth/sync/device_info + E2EE 本地状态）
        self._data_storage_backend: str = "json"
        self._pgsql_dsn: str = ""
        self._pgsql_schema: str = "public"
        self._pgsql_table_prefix: str = "matrix_store"
        self._e2ee_store_max_pending_writes: int = (
            _DEFAULT_E2EE_STORE_MAX_PENDING_WRITES
        )
        self._storage_backend_config: StorageBackendConfig = (
            StorageBackendConfig.create(
                backend=self._data_storage_backend,
                pgsql_dsn=self._pgsql_dsn,
                pgsql_schema=self._pgsql_schema,
                pgsql_table_prefix=self._pgsql_table_prefix,
            )
        )
