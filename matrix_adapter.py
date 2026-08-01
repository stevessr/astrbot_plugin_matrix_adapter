"""Compatibility exports for the Matrix platform adapter.

The implementation lives under :mod:`adapter.platform`; this module keeps the
historical root-level import path stable for AstrBot integrations and callers.
"""

from .adapter.platform import (
    MatrixPlatformAdapter,
    _cleanup_platform_registration,
    _inject_astrbot_field_metadata,
    _load_i18n_resources,
)

__all__ = [
    "MatrixPlatformAdapter",
    "_cleanup_platform_registration",
    "_inject_astrbot_field_metadata",
    "_load_i18n_resources",
]
