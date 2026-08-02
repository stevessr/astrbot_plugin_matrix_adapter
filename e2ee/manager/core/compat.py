"""Compatibility helpers for patchable manager-core dependencies."""

import sys

from ....config.plugin import get_plugin_config as _DEFAULT_GET_PLUGIN_CONFIG
from ...olm import VODOZEMAC_AVAILABLE as _DEFAULT_VODOZEMAC_AVAILABLE


def resolve_manager_symbol(name: str, default):
    """Resolve a dependency from the compatibility package namespace."""
    package = sys.modules.get(__package__)
    return getattr(package, name, default) if package is not None else default


def resolve_plugin_config():
    """Resolve the patchable plugin-config getter used by ``E2EEManager``."""
    getter = resolve_manager_symbol(
        "get_plugin_config",
        _DEFAULT_GET_PLUGIN_CONFIG,
    )
    return getter()


def vodozemac_available() -> bool:
    """Resolve the patchable vodozemac availability flag."""
    return bool(
        resolve_manager_symbol(
            "VODOZEMAC_AVAILABLE",
            _DEFAULT_VODOZEMAC_AVAILABLE,
        )
    )
