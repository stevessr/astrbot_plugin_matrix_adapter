"""Layered Matrix sync manager implementation."""

from ..sync_lib import (
    MatrixSyncManagerCallbacksMixin,
    MatrixSyncManagerDispatchMixin,
)
from .lifecycle import MatrixSyncManagerLifecycleMixin
from .loop import MatrixSyncManagerLoopMixin
from .state import MatrixSyncManagerStateMixin
from .tokens import MatrixSyncManagerTokenMixin


class MatrixSyncManager(
    MatrixSyncManagerStateMixin,
    MatrixSyncManagerLoopMixin,
    MatrixSyncManagerTokenMixin,
    MatrixSyncManagerLifecycleMixin,
    MatrixSyncManagerCallbacksMixin,
    MatrixSyncManagerDispatchMixin,
):
    """Compose Matrix sync state, loop, token, and callback behavior."""

    pass


__all__ = [
    "MatrixSyncManager",
    "MatrixSyncManagerCallbacksMixin",
    "MatrixSyncManagerDispatchMixin",
    "MatrixSyncManagerLifecycleMixin",
    "MatrixSyncManagerLoopMixin",
    "MatrixSyncManagerStateMixin",
    "MatrixSyncManagerTokenMixin",
]
