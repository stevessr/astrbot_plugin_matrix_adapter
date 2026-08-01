"""
插件级别配置管理

用于管理插件级别的配置（如目录路径），这些配置由所有 Matrix 适配器实例共享。
"""

from pathlib import Path

from .plugin_config_defaults import (
    _DEFAULT_E2EE_STORE_MAX_PENDING_WRITES,
    _DEFAULT_HTTP_TIMEOUT_SECONDS,
    _DEFAULT_MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES,
    _DEFAULT_MEDIA_UPLOAD_ALLOWED_MIME_RULES,
    _DEFAULT_MEDIA_UPLOAD_BLOCKED_EXTENSIONS,
    _DEFAULT_QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY,
    PluginConfigDefaultsMixin,
    _get_default_data_dir,
    _normalize_bool,
    _normalize_message_type,
    _normalize_non_negative_int,
    _normalize_pgsql_schema,
    _normalize_pgsql_table_prefix,
    _normalize_token_list,
    _warn_config_coercion,
)
from .storage_backend import StorageBackendConfig, normalize_storage_backend


class PluginConfig(PluginConfigDefaultsMixin):
    """单例类，存储插件级别的配置"""

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

    def initialize(self, config: dict):
        """从配置字典初始化插件配置

        Args:
            config: 插件配置字典，来自 context.get_config().get("plugin_config", {}).get("astrbot_plugin_matrix_adapter", {})
        """
        # 路径配置不再允许配置，直接使用默认值
        self._data_dir = _get_default_data_dir()
        self._store_path = self._data_dir / "store"
        self._e2ee_store_path = self._data_dir / "e2ee"
        self._media_cache_dir = self._data_dir / "media"

        # 其他配置仍然允许配置
        media_obj = config.get("matrix_media")
        auto_download_obj = config.get("matrix_auto_download")
        media_rules_obj = config.get("matrix_media_rules")

        http_timeout_seconds = None
        media_cache_gc_days = None
        media_download_concurrency = None
        quoted_media_background_download_concurrency = None
        media_download_min_interval_ms = None
        media_download_breaker_fail_threshold = None
        media_download_breaker_cooldown_ms = None
        media_download_breaker_max_cooldown_ms = None
        media_cache_index_persist = None
        media_download_max_in_memory_bytes = None
        if isinstance(media_obj, dict):
            if isinstance(media_obj.get("http_timeout_seconds"), (int, float, str)):
                http_timeout_seconds = media_obj.get("http_timeout_seconds")
            if isinstance(media_obj.get("cache_gc_days"), (int, float, str)):
                media_cache_gc_days = media_obj.get("cache_gc_days")
            if isinstance(media_obj.get("download_concurrency"), (int, float, str)):
                media_download_concurrency = media_obj.get("download_concurrency")
            if isinstance(
                media_obj.get("quoted_background_download_concurrency"),
                (int, float, str),
            ):
                quoted_media_background_download_concurrency = media_obj.get(
                    "quoted_background_download_concurrency"
                )
            if isinstance(media_obj.get("download_min_interval_ms"), (int, float, str)):
                media_download_min_interval_ms = media_obj.get(
                    "download_min_interval_ms"
                )
            if isinstance(
                media_obj.get("download_breaker_fail_threshold"), (int, float, str)
            ):
                media_download_breaker_fail_threshold = media_obj.get(
                    "download_breaker_fail_threshold"
                )
            if isinstance(
                media_obj.get("download_breaker_cooldown_ms"), (int, float, str)
            ):
                media_download_breaker_cooldown_ms = media_obj.get(
                    "download_breaker_cooldown_ms"
                )
            if isinstance(
                media_obj.get("download_breaker_max_cooldown_ms"), (int, float, str)
            ):
                media_download_breaker_max_cooldown_ms = media_obj.get(
                    "download_breaker_max_cooldown_ms"
                )
            if isinstance(media_obj.get("cache_index_persist"), (bool, str)):
                media_cache_index_persist = media_obj.get("cache_index_persist")
            if isinstance(
                media_obj.get("download_max_in_memory_bytes"), (int, float, str)
            ):
                media_download_max_in_memory_bytes = media_obj.get(
                    "download_max_in_memory_bytes"
                )

        if http_timeout_seconds is None:
            http_timeout_seconds = config.get("matrix_http_timeout_seconds")
        if media_cache_gc_days is None:
            media_cache_gc_days = config.get("matrix_media_cache_gc_days")
        if media_download_concurrency is None:
            media_download_concurrency = config.get("matrix_media_download_concurrency")
        if quoted_media_background_download_concurrency is None:
            quoted_media_background_download_concurrency = config.get(
                "matrix_quoted_media_background_download_concurrency"
            )
        if media_download_min_interval_ms is None:
            media_download_min_interval_ms = config.get(
                "matrix_media_download_min_interval_ms"
            )
        if media_download_breaker_fail_threshold is None:
            media_download_breaker_fail_threshold = config.get(
                "matrix_media_download_breaker_fail_threshold"
            )
        if media_download_breaker_cooldown_ms is None:
            media_download_breaker_cooldown_ms = config.get(
                "matrix_media_download_breaker_cooldown_ms"
            )
        if media_download_breaker_max_cooldown_ms is None:
            media_download_breaker_max_cooldown_ms = config.get(
                "matrix_media_download_breaker_max_cooldown_ms"
            )
        if media_cache_index_persist is None:
            media_cache_index_persist = config.get("matrix_media_cache_index_persist")
        if media_download_max_in_memory_bytes is None:
            media_download_max_in_memory_bytes = config.get(
                "matrix_media_download_max_in_memory_bytes"
            )

        self._http_timeout_seconds = _normalize_non_negative_int(
            http_timeout_seconds,
            _DEFAULT_HTTP_TIMEOUT_SECONDS,
            min_value=5,
            config_key="matrix_media.http_timeout_seconds",
        )
        self._media_cache_gc_days = _normalize_non_negative_int(
            media_cache_gc_days,
            30,
            min_value=0,
            config_key="matrix_media.cache_gc_days",
        )
        self._media_download_concurrency = _normalize_non_negative_int(
            media_download_concurrency,
            4,
            min_value=1,
            config_key="matrix_media.download_concurrency",
        )
        self._quoted_media_background_download_concurrency = (
            _normalize_non_negative_int(
                quoted_media_background_download_concurrency,
                _DEFAULT_QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY,
                min_value=1,
                config_key="matrix_media.quoted_background_download_concurrency",
            )
        )
        self._media_download_min_interval_ms = _normalize_non_negative_int(
            media_download_min_interval_ms,
            0,
            min_value=0,
            config_key="matrix_media.download_min_interval_ms",
        )
        self._media_download_breaker_fail_threshold = _normalize_non_negative_int(
            media_download_breaker_fail_threshold,
            6,
            min_value=0,
            config_key="matrix_media.download_breaker_fail_threshold",
        )
        self._media_download_breaker_cooldown_ms = _normalize_non_negative_int(
            media_download_breaker_cooldown_ms,
            5000,
            min_value=0,
            config_key="matrix_media.download_breaker_cooldown_ms",
        )
        self._media_download_breaker_max_cooldown_ms = _normalize_non_negative_int(
            media_download_breaker_max_cooldown_ms,
            120000,
            min_value=0,
            config_key="matrix_media.download_breaker_max_cooldown_ms",
        )
        self._media_cache_index_persist = _normalize_bool(
            media_cache_index_persist, True
        )
        self._media_download_max_in_memory_bytes = _normalize_non_negative_int(
            media_download_max_in_memory_bytes,
            _DEFAULT_MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES,
            min_value=0,
            config_key="matrix_media.download_max_in_memory_bytes",
        )

        media_auto_download_max_bytes = None
        media_auto_download_image = None
        media_auto_download_video = None
        media_auto_download_audio = None
        media_auto_download_file = None
        media_auto_download_sticker = None
        if isinstance(auto_download_obj, dict):
            if isinstance(auto_download_obj.get("max_bytes"), (int, float, str)):
                media_auto_download_max_bytes = auto_download_obj.get("max_bytes")
            if isinstance(auto_download_obj.get("image"), (bool, str)):
                media_auto_download_image = auto_download_obj.get("image")
            if isinstance(auto_download_obj.get("video"), (bool, str)):
                media_auto_download_video = auto_download_obj.get("video")
            if isinstance(auto_download_obj.get("audio"), (bool, str)):
                media_auto_download_audio = auto_download_obj.get("audio")
            if isinstance(auto_download_obj.get("file"), (bool, str)):
                media_auto_download_file = auto_download_obj.get("file")
            if isinstance(auto_download_obj.get("sticker"), (bool, str)):
                media_auto_download_sticker = auto_download_obj.get("sticker")

        if media_auto_download_max_bytes is None:
            media_auto_download_max_bytes = config.get(
                "matrix_media_auto_download_max_bytes"
            )
        if media_auto_download_image is None:
            media_auto_download_image = config.get("matrix_media_auto_download_image")
        if media_auto_download_video is None:
            media_auto_download_video = config.get("matrix_media_auto_download_video")
        if media_auto_download_audio is None:
            media_auto_download_audio = config.get("matrix_media_auto_download_audio")
        if media_auto_download_file is None:
            media_auto_download_file = config.get("matrix_media_auto_download_file")
        if media_auto_download_sticker is None:
            media_auto_download_sticker = config.get(
                "matrix_media_auto_download_sticker"
            )

        self._media_auto_download_max_bytes = _normalize_non_negative_int(
            media_auto_download_max_bytes,
            0,
            min_value=0,
            config_key="matrix_auto_download.max_bytes",
        )
        self._media_auto_download_image = _normalize_bool(
            media_auto_download_image, True
        )
        self._media_auto_download_video = _normalize_bool(
            media_auto_download_video, True
        )
        self._media_auto_download_audio = _normalize_bool(
            media_auto_download_audio, True
        )
        self._media_auto_download_file = _normalize_bool(media_auto_download_file, True)
        self._media_auto_download_sticker = _normalize_bool(
            media_auto_download_sticker, True
        )

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
        # 消息类型配置
        self._force_message_type = _normalize_message_type(
            config.get("matrix_force_message_type"),
            config.get("matrix_force_private_message"),
        )
        raw_force_type = config.get("matrix_force_message_type")
        if raw_force_type is not None:
            normalized_force_type = (
                raw_force_type.strip().lower()
                if isinstance(raw_force_type, str)
                else raw_force_type
            )
            if normalized_force_type != self._force_message_type:
                _warn_config_coercion(
                    config_key="matrix_force_message_type",
                    raw_value=raw_force_type,
                    normalized_value=self._force_message_type,
                    reason="invalid or legacy message type value",
                )

        # 回复自适应配置
        self._adaptive_thread_reply = _normalize_bool(
            config.get("matrix_adaptive_thread_reply"), True
        )

        # 输入状态与已读回执配置
        self._send_typing = _normalize_bool(config.get("matrix_send_typing"), False)
        self._send_read_receipt = _normalize_bool(
            config.get("matrix_send_read_receipt"), True
        )

        # 数据存储后端配置
        self._data_storage_backend = normalize_storage_backend(
            config.get("matrix_data_storage_backend", "json")
        )
        pgsql_obj = config.get("matrix_pgsql")
        pgsql_dsn = None
        pgsql_schema = None
        pgsql_table_prefix = None
        if isinstance(pgsql_obj, dict):
            pgsql_dsn = pgsql_obj.get("dsn")
            pgsql_schema = pgsql_obj.get("schema")
            pgsql_table_prefix = pgsql_obj.get("table_prefix")

        # 兼容旧配置：matrix_pgsql_dsn / matrix_pgsql_schema / matrix_pgsql_table_prefix
        if pgsql_dsn is None:
            pgsql_dsn = config.get("matrix_pgsql_dsn", "")
        if pgsql_schema is None:
            pgsql_schema = config.get("matrix_pgsql_schema")
        if pgsql_table_prefix is None:
            pgsql_table_prefix = config.get("matrix_pgsql_table_prefix")

        self._pgsql_dsn = str(pgsql_dsn or "").strip()
        self._pgsql_schema = _normalize_pgsql_schema(pgsql_schema)
        self._pgsql_table_prefix = _normalize_pgsql_table_prefix(pgsql_table_prefix)
        self._e2ee_store_max_pending_writes = _normalize_non_negative_int(
            config.get("matrix_e2ee_store_max_pending_writes"),
            _DEFAULT_E2EE_STORE_MAX_PENDING_WRITES,
            min_value=1,
            config_key="matrix_e2ee_store_max_pending_writes",
        )

        if self._data_storage_backend == "pgsql" and not self._pgsql_dsn:
            raise ValueError(
                "matrix_data_storage_backend=pgsql requires matrix_pgsql.dsn "
                "(or legacy matrix_pgsql_dsn)"
            )

        self._storage_backend_config = StorageBackendConfig.create(
            backend=self._data_storage_backend,
            pgsql_dsn=self._pgsql_dsn,
            pgsql_schema=self._pgsql_schema,
            pgsql_table_prefix=self._pgsql_table_prefix,
        )


# 全局单例实例
_plugin_config = PluginConfig()


def get_plugin_config() -> PluginConfig:
    """获取插件配置单例"""
    return _plugin_config


def init_plugin_config(config: dict):
    """初始化插件配置

    Args:
        config: 插件配置字典
    """
    _plugin_config.initialize(config)
