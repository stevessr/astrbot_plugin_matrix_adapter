"""Matrix sync loop and request execution."""

from .core import MatrixSyncManagerLoopOrchestratorMixin
from .failure import MatrixSyncManagerLoopFailureMixin
from .network import MatrixSyncManagerLoopNetworkMixin
from .request import MatrixSyncManagerLoopRequestMixin
from .success import MatrixSyncManagerLoopSuccessMixin


class MatrixSyncManagerLoopMixin(MatrixSyncManagerLoopOrchestratorMixin):
    """Run Matrix sync requests and process their responses."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixSyncManagerLoopOrchestratorMixin,
    MatrixSyncManagerLoopFailureMixin,
    MatrixSyncManagerLoopNetworkMixin,
    MatrixSyncManagerLoopRequestMixin,
    MatrixSyncManagerLoopSuccessMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixSyncManagerLoopMixin, _method_name, _method)


__all__ = [
    "MatrixSyncManagerLoopFailureMixin",
    "MatrixSyncManagerLoopMixin",
    "MatrixSyncManagerLoopNetworkMixin",
    "MatrixSyncManagerLoopOrchestratorMixin",
    "MatrixSyncManagerLoopRequestMixin",
    "MatrixSyncManagerLoopSuccessMixin",
]
