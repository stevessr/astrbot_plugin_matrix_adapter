"""
插件级别配置管理

用于管理插件级别的配置（如目录路径），这些配置由所有 Matrix 适配器实例共享。
"""

from pathlib import Path
from typing import Optional

from astrbot.api import logger
from astrbot.api.star import StarTools

from .storage_backend import StorageBackendConfig, normalize_storage_backend

_DEFAULT_MEDIA_UPLOAD_BLOCKED_EXTENSIONS = (
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
)
_DEFAULT_MEDIA_UPLOAD_ALLOWED_MIME_RULES = (
    "image/*",
    "video/*",
    "audio/*",
    "text/*",
    "application/pdf",
    "application/json",
    "application/zip",
    "application/octet-stream",
)
_DEFAULT_HTTP_TIMEOUT_SECONDS = 120
_DEFAULT_E2EE_STORE_MAX_PENDING_WRITES = 256
_DEFAULT_QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY = 2
_DEFAULT_MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES = 32 * 1024 * 1024


def _get_default_data_dir() -> Path:
    """获取插件默认数据目录"""
    try:
        return StarTools.get_data_dir("astrbot_plugin_matrix_adapter")
    except Exception:
        # 如果 StarTools 未初始化（如在测试环境），返回临时默认值
        return Path("./data/plugin_data/astrbot_plugin_matrix_adapter")


def _normalize_message_type(value, legacy_value) -> str:
    """归一化消息类型配置"""
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"auto", "private", "group", "stalk"}:
            return normalized
    if isinstance(value, bool):
        return "private" if value else "auto"
    if isinstance(legacy_value, bool):
        return "private" if legacy_value else "auto"
    return "auto"


def _warn_config_coercion(
    config_key: str,
    raw_value,
    normalized_value,
    reason: str,
) -> None:
    logger.warning(
        f"Config {config_key} coerced: raw={raw_value!r}, "
        f"normalized={normalized_value!r} ({reason})"
    )


def _normalize_pgsql_schema(value) -> str:
    if isinstance(value, str):
        normalized = value.strip()
        if normalized:
            return normalized
    return "public"


def _normalize_pgsql_table_prefix(value) -> str:
    if isinstance(value, str):
        normalized = value.strip()
        if normalized:
            return normalized
    return "matrix_store"


def _normalize_bool(value, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    return default


def _normalize_non_negative_int(
    value,
    default: int = 0,
    *,
    min_value: int = 0,
    config_key: str | None = None,
) -> int:
    if value is None:
        return default
    try:
        normalized = int(value)
    except Exception:
        if config_key:
            _warn_config_coercion(
                config_key=config_key,
                raw_value=value,
                normalized_value=default,
                reason="invalid integer, fallback to default",
            )
        return default
    if normalized < min_value:
        if config_key:
            _warn_config_coercion(
                config_key=config_key,
                raw_value=value,
                normalized_value=min_value,
                reason=f"value below minimum {min_value}",
            )
        return min_value
    return normalized


def _normalize_token_list(
    value,
    default: tuple[str, ...],
    *,
    extension_mode: bool = False,
    config_key: str | None = None,
) -> tuple[str, ...]:
    raw_tokens: list[str] = []
    if isinstance(value, str):
        raw_tokens = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        raw_tokens = [str(item) for item in value if isinstance(item, str)]
    else:
        if value is not None and config_key:
            _warn_config_coercion(
                config_key=config_key,
                raw_value=value,
                normalized_value=default,
                reason="invalid list type, fallback to default",
            )
        return default

    normalized_tokens: list[str] = []
    changed = False
    for token in raw_tokens:
        original = token
        normalized = token.strip().lower()
        if not normalized:
            changed = True
            continue
        if extension_mode and normalized != "*" and not normalized.startswith("."):
            normalized = f".{normalized}"
            changed = True
        if normalized != original:
            changed = True
        if normalized not in normalized_tokens:
            normalized_tokens.append(normalized)
        else:
            changed = True

    if not normalized_tokens:
        if config_key and value is not None:
            _warn_config_coercion(
                config_key=config_key,
                raw_value=value,
                normalized_value=default,
                reason="no valid tokens, fallback to default",
            )
        return default

    result = tuple(normalized_tokens)
    if changed and config_key:
        _warn_config_coercion(
            config_key=config_key,
            raw_value=value,
            normalized_value=result,
            reason="normalized tokens",
        )
    return result


class PluginConfig:
    """单例类，存储插件级别的配置"""

    _instance: Optional["PluginConfig"] = None
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
        self._oauth2_callback_port: int = 8765
        self._oauth2_callback_host: str = "127.0.0.1"
        # 消息类型配置
        self._force_message_type: str = "auto"
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
        self._oauth2_callback_port = config.get("matrix_oauth2_callback_port", 8765)
        self._oauth2_callback_host = config.get(
            "matrix_oauth2_callback_host", "127.0.0.1"
        )
        self._http_timeout_seconds = _normalize_non_negative_int(
            config.get("matrix_http_timeout_seconds"),
            _DEFAULT_HTTP_TIMEOUT_SECONDS,
            min_value=5,
            config_key="matrix_http_timeout_seconds",
        )
        self._media_cache_gc_days = _normalize_non_negative_int(
            config.get("matrix_media_cache_gc_days"),
            30,
            min_value=0,
            config_key="matrix_media_cache_gc_days",
        )
        self._media_download_concurrency = _normalize_non_negative_int(
            config.get("matrix_media_download_concurrency"),
            4,
            min_value=1,
            config_key="matrix_media_download_concurrency",
        )
        self._quoted_media_background_download_concurrency = (
            _normalize_non_negative_int(
                config.get("matrix_quoted_media_background_download_concurrency"),
                _DEFAULT_QUOTED_MEDIA_BACKGROUND_DOWNLOAD_CONCURRENCY,
                min_value=1,
                config_key="matrix_quoted_media_background_download_concurrency",
            )
        )
        self._media_download_min_interval_ms = _normalize_non_negative_int(
            config.get("matrix_media_download_min_interval_ms"),
            0,
            min_value=0,
            config_key="matrix_media_download_min_interval_ms",
        )
        self._media_download_breaker_fail_threshold = _normalize_non_negative_int(
            config.get("matrix_media_download_breaker_fail_threshold"),
            6,
            min_value=0,
            config_key="matrix_media_download_breaker_fail_threshold",
        )
        self._media_download_breaker_cooldown_ms = _normalize_non_negative_int(
            config.get("matrix_media_download_breaker_cooldown_ms"),
            5000,
            min_value=0,
            config_key="matrix_media_download_breaker_cooldown_ms",
        )
        self._media_download_breaker_max_cooldown_ms = _normalize_non_negative_int(
            config.get("matrix_media_download_breaker_max_cooldown_ms"),
            120000,
            min_value=0,
            config_key="matrix_media_download_breaker_max_cooldown_ms",
        )
        self._media_cache_index_persist = _normalize_bool(
            config.get("matrix_media_cache_index_persist"), True
        )
        self._media_auto_download_max_bytes = _normalize_non_negative_int(
            config.get("matrix_media_auto_download_max_bytes"),
            0,
            min_value=0,
            config_key="matrix_media_auto_download_max_bytes",
        )
        self._media_download_max_in_memory_bytes = _normalize_non_negative_int(
            config.get("matrix_media_download_max_in_memory_bytes"),
            _DEFAULT_MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES,
            min_value=0,
            config_key="matrix_media_download_max_in_memory_bytes",
        )
        self._media_auto_download_image = _normalize_bool(
            config.get("matrix_media_auto_download_image"), True
        )
        self._media_auto_download_video = _normalize_bool(
            config.get("matrix_media_auto_download_video"), True
        )
        self._media_auto_download_audio = _normalize_bool(
            config.get("matrix_media_auto_download_audio"), True
        )
        self._media_auto_download_file = _normalize_bool(
            config.get("matrix_media_auto_download_file"), True
        )
        self._media_auto_download_sticker = _normalize_bool(
            config.get("matrix_media_auto_download_sticker"), True
        )
        self._media_upload_strict_mime_check = _normalize_bool(
            config.get("matrix_media_upload_strict_mime_check"), True
        )
        self._media_upload_blocked_extensions = _normalize_token_list(
            config.get("matrix_media_upload_blocked_extensions"),
            _DEFAULT_MEDIA_UPLOAD_BLOCKED_EXTENSIONS,
            extension_mode=True,
            config_key="matrix_media_upload_blocked_extensions",
        )
        self._media_upload_allowed_mime_rules = _normalize_token_list(
            config.get("matrix_media_upload_allowed_mime_rules"),
            _DEFAULT_MEDIA_UPLOAD_ALLOWED_MIME_RULES,
            config_key="matrix_media_upload_allowed_mime_rules",
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

    @property
    def store_path(self) -> Path:
        """获取数据存储路径"""
        return self._store_path

    @property
    def e2ee_store_path(self) -> Path:
        """获取 E2EE 存储路径"""
        return self._e2ee_store_path

    @property
    def media_cache_dir(self) -> Path:
        """获取媒体缓存目录"""
        return self._media_cache_dir

    @property
    def media_cache_gc_days(self) -> int:
        """媒体缓存 GC 天数，<=0 表示禁用"""
        return self._media_cache_gc_days

    @property
    def http_timeout_seconds(self) -> int:
        """Global HTTP request timeout in seconds."""
        return self._http_timeout_seconds

    @property
    def media_download_concurrency(self) -> int:
        """媒体下载并发上限（每个媒体源 server）"""
        return self._media_download_concurrency

    @property
    def quoted_media_background_download_concurrency(self) -> int:
        """后台引用媒体下载并发上限"""
        return self._quoted_media_background_download_concurrency

    @property
    def media_download_min_interval_ms(self) -> int:
        """同一媒体源 server 的最小下载请求间隔（毫秒）"""
        return self._media_download_min_interval_ms

    @property
    def media_download_breaker_fail_threshold(self) -> int:
        """媒体下载熔断触发连续失败阈值，<=0 表示禁用"""
        return self._media_download_breaker_fail_threshold

    @property
    def media_download_breaker_cooldown_ms(self) -> int:
        """媒体下载熔断基础冷却时间（毫秒）"""
        return self._media_download_breaker_cooldown_ms

    @property
    def media_download_breaker_max_cooldown_ms(self) -> int:
        """媒体下载熔断最大冷却时间（毫秒）"""
        return self._media_download_breaker_max_cooldown_ms

    @property
    def media_cache_index_persist(self) -> bool:
        """是否启用媒体缓存索引持久化"""
        return self._media_cache_index_persist

    @property
    def media_auto_download_max_bytes(self) -> int:
        """媒体自动下载大小上限（字节），<=0 表示不限制"""
        return self._media_auto_download_max_bytes

    def is_media_auto_download_enabled(self, msgtype: str) -> bool:
        """检查指定媒体类型是否启用自动下载"""
        mapping = {
            "m.image": self._media_auto_download_image,
            "m.video": self._media_auto_download_video,
            "m.audio": self._media_auto_download_audio,
            "m.file": self._media_auto_download_file,
            "m.sticker": self._media_auto_download_sticker,
        }
        return mapping.get(msgtype, False)

    @property
    def media_download_max_in_memory_bytes(self) -> int:
        """下载返回 bytes 时的内存上限（字节），<=0 表示不限制"""
        return self._media_download_max_in_memory_bytes

    @property
    def media_upload_strict_mime_check(self) -> bool:
        """媒体上传时是否启用严格 MIME 校验"""
        return self._media_upload_strict_mime_check

    @property
    def media_upload_blocked_extensions(self) -> tuple[str, ...]:
        """媒体上传扩展名黑名单"""
        return self._media_upload_blocked_extensions

    @property
    def media_upload_allowed_mime_rules(self) -> tuple[str, ...]:
        """媒体上传允许的 MIME 规则"""
        return self._media_upload_allowed_mime_rules

    @property
    def oauth2_callback_port(self) -> int:
        """获取 OAuth2 回调服务器端口"""
        return self._oauth2_callback_port

    @property
    def oauth2_callback_host(self) -> str:
        """获取 OAuth2 回调服务器主机地址"""
        return self._oauth2_callback_host

    @property
    def force_message_type(self) -> str:
        """强制消息类型（auto / private / group / stalk）"""
        return self._force_message_type

    @property
    def force_private_message(self) -> bool:
        """兼容旧配置：是否将所有消息强制视为私聊"""
        return self._force_message_type == "private"

    @property
    def data_storage_backend(self) -> str:
        """数据存储后端（json/sqlite/pgsql）"""
        return self._data_storage_backend

    @property
    def pgsql_dsn(self) -> str:
        """PostgreSQL DSN"""
        return self._pgsql_dsn

    @property
    def pgsql_schema(self) -> str:
        """PostgreSQL schema"""
        return self._pgsql_schema

    @property
    def pgsql_table_prefix(self) -> str:
        """PostgreSQL 表名前缀"""
        return self._pgsql_table_prefix

    @property
    def e2ee_store_max_pending_writes(self) -> int:
        """E2EE store async persistence pending queue limit"""
        return self._e2ee_store_max_pending_writes

    @property
    def storage_backend_config(self) -> StorageBackendConfig:
        """运行时固定存储后端配置对象。"""
        return self._storage_backend_config

    @property
    def data_dir(self) -> Path:
        """插件数据目录"""
        return self._data_dir or _get_default_data_dir()


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
