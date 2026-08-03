"""Shared configuration access for message handler operations."""


def _get_plugin_config():
    from . import get_plugin_config

    return get_plugin_config()
