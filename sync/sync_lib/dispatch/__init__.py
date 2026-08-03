"""Composable Matrix sync dispatch operations."""

import asyncio
from collections.abc import Callable

from astrbot.api import logger

from .guard import MatrixSyncManagerCallbackGuardMixin
from .routing import MatrixSyncManagerEventRoutingMixin


class MatrixSyncManagerDispatchMixin(
    MatrixSyncManagerEventRoutingMixin,
    MatrixSyncManagerCallbackGuardMixin,
):
    """Event dispatch logic for MatrixSyncManager."""

    pass


# Preserve direct method attributes exposed by the former mixin.
for _mixin in (
    MatrixSyncManagerEventRoutingMixin,
    MatrixSyncManagerCallbackGuardMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if callable(_method) and not _method_name.startswith("__"):
            setattr(MatrixSyncManagerDispatchMixin, _method_name, _method)


__all__ = [
    "Callable",
    "MatrixSyncManagerCallbackGuardMixin",
    "MatrixSyncManagerDispatchMixin",
    "MatrixSyncManagerEventRoutingMixin",
    "asyncio",
    "logger",
]
