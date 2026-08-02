"""Compatibility helpers for patchable cross-signing core dependencies."""

import sys

from ....config.plugin import get_plugin_config as _DEFAULT_GET_PLUGIN_CONFIG
from ...backup.crypto_utils import CRYPTO_AVAILABLE as _DEFAULT_CRYPTO_AVAILABLE
from ...constants import DEVICE_SECRET_REQUEST_PENDING, FORCE_OVERWRITE_SERVER_KEYS
from ...storage import build_e2ee_data_store as _DEFAULT_BUILD_E2EE_DATA_STORE


def resolve_core_symbol(name: str, default):
    """Resolve a dependency from the compatibility package namespace."""
    package = sys.modules.get(__package__)
    return getattr(package, name, default) if package is not None else default


__all__ = [
    "_DEFAULT_BUILD_E2EE_DATA_STORE",
    "_DEFAULT_CRYPTO_AVAILABLE",
    "_DEFAULT_GET_PLUGIN_CONFIG",
    "DEVICE_SECRET_REQUEST_PENDING",
    "FORCE_OVERWRITE_SERVER_KEYS",
    "resolve_core_symbol",
]
