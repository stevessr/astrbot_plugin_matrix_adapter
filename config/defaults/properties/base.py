"""Default-backed configuration properties: paths and network."""

from pathlib import Path

from ..values import _get_default_data_dir


class PluginConfigDefaultsBaseMixin:
    """路径与网络相关的默认配置属性。"""

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
    def http_timeout_seconds(self) -> int:
        """Global HTTP request timeout in seconds."""
        return self._http_timeout_seconds

    @property
    def data_dir(self) -> Path:
        """插件数据目录"""
        return self._data_dir or _get_default_data_dir()
