"""Plugin config access for session sends."""


def _get_plugin_config():
    from .. import get_plugin_config

    return get_plugin_config()
