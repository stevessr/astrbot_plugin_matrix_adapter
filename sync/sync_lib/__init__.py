from .callbacks import MatrixSyncManagerCallbacksMixin
from .dispatch import MatrixSyncManagerDispatchMixin


class MatrixSyncManagerMixin(
    MatrixSyncManagerCallbacksMixin,
    MatrixSyncManagerDispatchMixin,
):
    """Combined sync-manager mixin."""

    pass


__all__ = [
    "MatrixSyncManagerCallbacksMixin",
    "MatrixSyncManagerDispatchMixin",
    "MatrixSyncManagerMixin",
]
