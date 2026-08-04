"""Default-backed configuration properties."""

from .base import PluginConfigDefaultsBaseMixin
from .media import PluginConfigDefaultsMediaMixin
from .message import PluginConfigDefaultsMessageMixin
from .storage import PluginConfigDefaultsStorageMixin


class PluginConfigDefaultsMixin(
    PluginConfigDefaultsBaseMixin,
    PluginConfigDefaultsMediaMixin,
    PluginConfigDefaultsMessageMixin,
    PluginConfigDefaultsStorageMixin,
):
    """插件配置默认值 mixin：提供默认配置常量辅助函数与全部配置属性的 getter"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _mixin in (
    PluginConfigDefaultsBaseMixin,
    PluginConfigDefaultsMediaMixin,
    PluginConfigDefaultsMessageMixin,
    PluginConfigDefaultsStorageMixin,
):
    for _name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod, property)) or callable(
            _method
        ):
            setattr(PluginConfigDefaultsMixin, _name, _method)

__all__ = ["PluginConfigDefaultsMixin"]
