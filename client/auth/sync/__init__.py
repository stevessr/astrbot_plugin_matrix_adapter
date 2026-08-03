"""Composable Matrix synchronization and sync-filter operations."""

from typing import Any

from astrbot.api import logger

from ....constants import DEFAULT_TIMEOUT_MS_30000
from ...path_utils import quote_path_segment
from .filters import AuthSyncFilterMixin
from .polling import AuthSyncPollingMixin


class AuthSyncMixin(
    AuthSyncPollingMixin,
    AuthSyncFilterMixin,
):
    """Synchronize client state and manage sync filters."""

    pass


# Preserve direct method attributes exposed by the former mixin.
AuthSyncMixin.sync = AuthSyncPollingMixin.__dict__["sync"]
AuthSyncMixin.create_filter = AuthSyncFilterMixin.__dict__["create_filter"]
AuthSyncMixin.get_filter = AuthSyncFilterMixin.__dict__["get_filter"]


__all__ = [
    "Any",
    "AuthSyncMixin",
    "DEFAULT_TIMEOUT_MS_30000",
    "logger",
    "quote_path_segment",
]
