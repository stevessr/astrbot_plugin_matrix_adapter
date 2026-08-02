"""Compatibility helpers for patchable SSSS crypto dependencies."""

import sys

from ...backup.crypto_utils import CRYPTO_AVAILABLE as _DEFAULT_CRYPTO_AVAILABLE


def resolve_ssss_symbol(name: str, default):
    """Resolve a dependency from the SSSS crypto package namespace."""
    package = sys.modules.get(__package__)
    return getattr(package, name, default) if package is not None else default


def crypto_available(default: bool = _DEFAULT_CRYPTO_AVAILABLE) -> bool:
    """Resolve the current cryptography availability flag."""
    return bool(resolve_ssss_symbol("CRYPTO_AVAILABLE", default))


__all__ = [
    "_DEFAULT_CRYPTO_AVAILABLE",
    "crypto_available",
    "resolve_ssss_symbol",
]
