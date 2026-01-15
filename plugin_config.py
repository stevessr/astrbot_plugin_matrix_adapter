"""
插件级别配置管理

用于管理插件级别的配置（如目录路径），这些配置由所有 Matrix 适配器实例共享。
"""

from pathlib import Path
from typing import Optional

from astrbot.api.star import StarTools


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
        # 流式发送配置
        self._streaming_no_edit: bool = False

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
        # 流式发送配置
        self._streaming_no_edit = config.get("matrix_streaming_no_edit", False)

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
    def streaming_no_edit(self) -> bool:
        """流式发送时是否禁用编辑（等待完成后一次性发送）"""
        return self._streaming_no_edit


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
