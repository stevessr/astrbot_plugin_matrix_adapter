"""Default-backed configuration properties."""

from pathlib import Path

from ...storage.backend import StorageBackendConfig
from .values import _get_default_data_dir


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
