"""Compatibility lookup for patchable send-device SAS availability."""

import sys

from ...constants import VODOZEMAC_SAS_AVAILABLE


def _vodozemac_sas_available() -> bool:
    parent_package = sys.modules.get(__package__.rsplit(".", 1)[0])
    if parent_package is not None:
        return bool(
            getattr(parent_package, "VODOZEMAC_SAS_AVAILABLE", VODOZEMAC_SAS_AVAILABLE)
        )
    return VODOZEMAC_SAS_AVAILABLE
