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
        return Path("./data/astrbot_plugin_matrix_adapter")


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

        # 延迟初始化默认值（等待 StarTools 可用）
        self._store_path: str | None = None
        self._e2ee_store_path: str | None = None
        self._media_cache_dir: str | None = None
        self._oauth2_callback_port: int = 8765
        self._oauth2_callback_host: str = "127.0.0.1"
        # Sticker 相关配置
        self._sticker_auto_sync: bool = False
        self._sticker_sync_user_emotes: bool = False
        # 消息类型配置
        self._force_private_message: bool = False

    def _ensure_default_paths(self):
        """确保默认路径已初始化"""
        if self._data_dir is None:
            self._data_dir = _get_default_data_dir()
        if self._store_path is None:
            self._store_path = str(self._data_dir / "store")
        if self._e2ee_store_path is None:
            self._e2ee_store_path = str(self._data_dir / "e2ee")
        if self._media_cache_dir is None:
            self._media_cache_dir = str(self._data_dir / "media")

    def initialize(self, config: dict):
        """从配置字典初始化插件配置

        Args:
            config: 插件配置字典，来自 context.get_config().get("plugin_config", {}).get("astrbot_plugin_matrix_adapter", {})
        """
        self._data_dir = _get_default_data_dir()
        default_store = str(self._data_dir / "store")
        default_e2ee = str(self._data_dir / "e2ee")
        default_media = str(self._data_dir / "media")

        self._store_path = config.get("matrix_store_path", default_store)
        self._e2ee_store_path = config.get("matrix_e2ee_store_path", default_e2ee)
        self._media_cache_dir = config.get("matrix_media_cache_dir", default_media)
        self._oauth2_callback_port = config.get("matrix_oauth2_callback_port", 8765)
        self._oauth2_callback_host = config.get(
            "matrix_oauth2_callback_host", "127.0.0.1"
        )
        # Sticker 相关配置
        self._sticker_auto_sync = config.get("matrix_sticker_auto_sync", False)
        self._sticker_sync_user_emotes = config.get(
            "matrix_sticker_sync_user_emotes", False
        )
        # 消息类型配置
        self._force_private_message = config.get(
            "matrix_force_private_message", False
        )

    @property
    def store_path(self) -> str:
        """获取数据存储路径"""
        self._ensure_default_paths()
        return self._store_path

    @property
    def e2ee_store_path(self) -> str:
        """获取 E2EE 存储路径"""
        self._ensure_default_paths()
        return self._e2ee_store_path

    @property
    def media_cache_dir(self) -> str:
        """获取媒体缓存目录"""
        self._ensure_default_paths()
        return self._media_cache_dir

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
    def force_private_message(self) -> bool:
        """是否将所有消息强制视为私聊"""
        return self._force_private_message


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
