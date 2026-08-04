"""Resolve the vodozemac availability flag from the public flow-key package."""

import sys

from ...constants import VODOZEMAC_SAS_AVAILABLE


def _vodozemac_sas_available() -> bool:
    package = sys.modules.get(__package__.rsplit(".", 1)[0])
    if package is not None:
        return bool(
            getattr(package, "VODOZEMAC_SAS_AVAILABLE", VODOZEMAC_SAS_AVAILABLE)
        )
    return VODOZEMAC_SAS_AVAILABLE


__all__ = ["_vodozemac_sas_available"]
