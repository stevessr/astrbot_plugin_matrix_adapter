"""Matrix adapter configuration components."""

from importlib import import_module

__all__ = [
    "MatrixConfig",
    "PluginConfig",
    "get_plugin_config",
    "init_plugin_config",
]

_EXPORTS = {
    "MatrixConfig": (".matrix", "MatrixConfig"),
    "PluginConfig": (".plugin", "PluginConfig"),
    "get_plugin_config": (".plugin", "get_plugin_config"),
    "init_plugin_config": (".plugin", "init_plugin_config"),
}


def __getattr__(name: str):
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(name) from exc
    return getattr(import_module(module_name, __name__), attribute_name)
