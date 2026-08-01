"""Plugin-level configuration singleton and public accessors."""

from .core import PluginConfig

_plugin_config = PluginConfig()


def get_plugin_config() -> PluginConfig:
    """Return the shared plugin configuration singleton."""

    return _plugin_config


def init_plugin_config(config: dict):
    """Initialize the shared plugin configuration from a mapping."""

    _plugin_config.initialize(config)


__all__ = ["PluginConfig", "get_plugin_config", "init_plugin_config"]
