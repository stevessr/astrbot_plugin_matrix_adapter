"""Compatibility helpers for patchable in-room SAS flags."""

import sys

from ...constants import VODOZEMAC_SAS_AVAILABLE


def _vodozemac_sas_available() -> bool:
    """Resolve the availability flag from the public send-room package."""
    parent_name = __package__.rsplit(".", 1)[0]
    package = sys.modules.get(parent_name)
    if package is not None:
        return bool(
            getattr(package, "VODOZEMAC_SAS_AVAILABLE", VODOZEMAC_SAS_AVAILABLE)
        )
    return VODOZEMAC_SAS_AVAILABLE


__all__ = ["_vodozemac_sas_available"]
