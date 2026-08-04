"""Plugin configuration path defaults and orchestration."""

from ....defaults import _get_default_data_dir


class PluginConfigInitializationCoreMixin:
    """Initialize path defaults and orchestrate per-domain config phases."""

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

        self._initialize_media_settings(config)
        self._initialize_auto_download_settings(config)
        self._initialize_media_rules(config)
        self._initialize_message_settings(config)
        self._initialize_storage_settings(config)
