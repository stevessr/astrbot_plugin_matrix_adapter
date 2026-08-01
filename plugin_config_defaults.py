"""
插件级别配置默认值

包含默认配置常量、归一化辅助函数以及全部配置属性的 getter，由 PluginConfig 通过 MRO 组合使用。
"""

from pathlib import Path

from astrbot.api import logger
from astrbot.api.star import StarTools

from .storage.backend import StorageBackendConfig
from .utils import parse_bool

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


_normalize_bool = parse_bool


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


class PluginConfigDefaultsMixin:
    """插件配置默认值 mixin：提供默认配置常量辅助函数与全部配置属性的 getter"""

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
    def force_message_type(self) -> str:
        """强制消息类型（auto / private / group / stalk）"""
        return self._force_message_type

    @property
    def adaptive_thread_reply(self) -> bool:
        """回复自适应：入站消息在消息列内时，回复也留在同一消息列"""
        return self._adaptive_thread_reply

    @property
    def send_typing(self) -> bool:
        """是否发送「正在输入」（typing）状态"""
        return self._send_typing

    @property
    def send_read_receipt(self) -> bool:
        """是否在消息处理完成后发送已读回执"""
        return self._send_read_receipt

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
