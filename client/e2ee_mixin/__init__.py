"""Composable end-to-end encryption operations for the Matrix client."""

from typing import Any

from astrbot.api import logger

from ...constants import KEY_QUERY_TIMEOUT_MS_10000
from .keys import E2EEKeyMixin
from .signing import E2EESigningMixin


class E2EEMixin(
    E2EEKeyMixin,
    E2EESigningMixin,
):
    """End-to-end encryption methods for Matrix client"""

    pass


# Preserve direct method attributes exposed by the former mixin.
E2EEMixin.upload_keys = E2EEKeyMixin.__dict__["upload_keys"]
E2EEMixin.query_keys = E2EEKeyMixin.__dict__["query_keys"]
E2EEMixin.claim_keys = E2EEKeyMixin.__dict__["claim_keys"]
E2EEMixin.upload_signatures = E2EESigningMixin.__dict__["upload_signatures"]
E2EEMixin.upload_signing_keys = E2EESigningMixin.__dict__["upload_signing_keys"]
E2EEMixin.get_keys_changes = E2EESigningMixin.__dict__["get_keys_changes"]


__all__ = ["Any", "E2EEMixin", "KEY_QUERY_TIMEOUT_MS_10000", "logger"]
