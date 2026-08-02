"""Compatibility helpers for patchable upload-module dependencies."""

import sys

from ...backup.crypto_utils import CRYPTO_AVAILABLE as _DEFAULT_CRYPTO_AVAILABLE


def resolve_upload_symbol(name: str, default):
    """Resolve a dependency from the compatibility package namespace."""
    package = sys.modules.get(__package__)
    return getattr(package, name, default) if package is not None else default


__all__ = ["_DEFAULT_CRYPTO_AVAILABLE", "resolve_upload_symbol"]
