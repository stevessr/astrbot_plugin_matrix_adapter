"""Compatibility helpers for patchable crypto backend attributes."""

import sys


def resolve_attribute(name: str, default):
    """Resolve an attribute from the former module's package namespace."""
    package = sys.modules.get(__package__)
    return getattr(package, name, default) if package is not None else default


def crypto_available(default: bool) -> bool:
    """Resolve the package-level cryptography availability flag."""
    return bool(resolve_attribute("CRYPTO_AVAILABLE", default))


def vodozemac_pk_available(default: bool) -> bool:
    """Resolve the package-level vodozemac PkEncryption availability flag."""
    return bool(resolve_attribute("VODOZEMAC_PK_AVAILABLE", default))
