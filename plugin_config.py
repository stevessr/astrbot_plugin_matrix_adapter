"""
插件级别配置管理

用于管理插件级别的配置（如目录路径），这些配置由所有 Matrix 适配器实例共享。
"""

from pathlib import Path
from typing import Optional

from astrbot.api import logger
from astrbot.api.star import StarTools

from .storage_backend import normalize_storage_backend


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
        self._oauth2_callback_port: int = 8765
        self._oauth2_callback_host: str = "127.0.0.1"
        # Sticker 相关配置
        self._sticker_auto_sync: bool = False
        self._sticker_sync_user_emotes: bool = False
        # 消息类型配置
        self._force_message_type: str = "auto"
        # 数据存储后端（users/rooms/auth/sync/device_info + E2EE 本地状态）
        self._data_storage_backend: str = "json"
        self._pgsql_dsn: str = ""
        self._pgsql_schema: str = "public"
        self._pgsql_table_prefix: str = "matrix_store"
        # Emoji 短码转换配置
        self._emoji_shortcodes_enabled: bool = False

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
        self._media_cache_gc_days = config.get("matrix_media_cache_gc_days", 30)
        # Sticker 相关配置
        self._sticker_auto_sync = config.get("matrix_sticker_auto_sync", False)
        self._sticker_sync_user_emotes = config.get(
            "matrix_sticker_sync_user_emotes", False
        )
        # 消息类型配置
        self._force_message_type = _normalize_message_type(
            config.get("matrix_force_message_type"),
            config.get("matrix_force_private_message"),
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

        if self._data_storage_backend == "pgsql" and not self._pgsql_dsn:
            logger.warning(
                "matrix_data_storage_backend=pgsql 但未配置 matrix_pgsql.dsn（或旧字段 matrix_pgsql_dsn），已回退到 json",
                extra={"plugin_tag": "matrix", "short_levelname": "WARN"},
            )
            self._data_storage_backend = "json"

        # Emoji 短码配置（bool）
        self._emoji_shortcodes_enabled = _normalize_bool(
            config.get("matrix_emoji_shortcodes"), False
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
    def oauth2_callback_port(self) -> int:
        """获取 OAuth2 回调服务器端口"""
        return self._oauth2_callback_port

    @property
    def oauth2_callback_host(self) -> str:
        """获取 OAuth2 回调服务器主机地址"""
        return self._oauth2_callback_host

    @property
    def sticker_auto_sync(self) -> bool:
        """是否自动同步房间 Sticker 包"""
        return self._sticker_auto_sync

    @property
    def sticker_sync_user_emotes(self) -> bool:
        """是否同步用户级别 Sticker 包"""
        return self._sticker_sync_user_emotes

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
    def emoji_shortcodes_enabled(self) -> bool:
        """是否启用 Emoji 短码转换"""
        return self._emoji_shortcodes_enabled

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
