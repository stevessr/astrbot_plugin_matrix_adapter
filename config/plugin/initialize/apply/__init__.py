"""Configuration-dictionary initialization split by config domain.

Public symbols re-exported for backward compatibility.
"""

from .auto_download import PluginConfigInitializationAutoDownloadMixin
from .core import PluginConfigInitializationCoreMixin
from .media import PluginConfigInitializationMediaMixin
from .media_rules import PluginConfigInitializationMediaRulesMixin
from .message import PluginConfigInitializationMessageMixin
from .storage import PluginConfigInitializationStorageMixin


class PluginConfigInitializationOperationsMixin(
    PluginConfigInitializationCoreMixin,
    PluginConfigInitializationMediaMixin,
    PluginConfigInitializationAutoDownloadMixin,
    PluginConfigInitializationMediaRulesMixin,
    PluginConfigInitializationMessageMixin,
    PluginConfigInitializationStorageMixin,
):
    """Apply external configuration values to a PluginConfig instance."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    PluginConfigInitializationCoreMixin,
    PluginConfigInitializationMediaMixin,
    PluginConfigInitializationAutoDownloadMixin,
    PluginConfigInitializationMediaRulesMixin,
    PluginConfigInitializationMessageMixin,
    PluginConfigInitializationStorageMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(PluginConfigInitializationOperationsMixin, _method_name, _method)


__all__ = [
    "PluginConfigInitializationOperationsMixin",
    "PluginConfigInitializationCoreMixin",
    "PluginConfigInitializationMediaMixin",
    "PluginConfigInitializationAutoDownloadMixin",
    "PluginConfigInitializationMediaRulesMixin",
    "PluginConfigInitializationMessageMixin",
    "PluginConfigInitializationStorageMixin",
]
