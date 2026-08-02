"""Compatibility helpers for package-level MIME configuration patching."""

from importlib import import_module


def get_plugin_config():
    """Resolve the facade's configurable plugin accessor at call time."""
    return import_module(__package__).get_plugin_config()
