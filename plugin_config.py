"""
插件级别配置管理

用于管理插件级别的配置（如目录路径），这些配置由所有 Matrix 适配器实例共享。
"""

from typing import Optional


class PluginConfig:
    """单例类，存储插件级别的配置"""

    _instance: Optional["PluginConfig"] = None
    _initialized: bool = False

    # 默认值
    DEFAULT_STORE_PATH = "./data/matrix/store"
    DEFAULT_E2EE_STORE_PATH = "./data/matrix/e2ee"
    DEFAULT_MEDIA_CACHE_DIR = "./data/matrix/media"

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if PluginConfig._initialized:
            return
        PluginConfig._initialized = True

        # 初始化默认值
        self._store_path = self.DEFAULT_STORE_PATH
        self._e2ee_store_path = self.DEFAULT_E2EE_STORE_PATH
        self._media_cache_dir = self.DEFAULT_MEDIA_CACHE_DIR

    def initialize(self, config: dict):
        """从配置字典初始化插件配置

        Args:
            config: 插件配置字典，来自 context.get_config().get("plugin_config", {}).get("astrbot_plugin_matrix_adapter", {})
        """
        self._store_path = config.get("matrix_store_path", self.DEFAULT_STORE_PATH)
        self._e2ee_store_path = config.get(
            "matrix_e2ee_store_path", self.DEFAULT_E2EE_STORE_PATH
        )
        self._media_cache_dir = config.get(
            "matrix_media_cache_dir", self.DEFAULT_MEDIA_CACHE_DIR
        )

    @property
    def store_path(self) -> str:
        """获取数据存储路径"""
        return self._store_path

    @property
    def e2ee_store_path(self) -> str:
        """获取 E2EE 存储路径"""
        return self._e2ee_store_path

    @property
    def media_cache_dir(self) -> str:
        """获取媒体缓存目录"""
        return self._media_cache_dir


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
