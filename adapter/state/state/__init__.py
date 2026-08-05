"""Runtime health state for one Matrix adapter instance."""

from .init import MatrixRuntimeStateInitMixin
from .marks import MatrixRuntimeStateMarksMixin
from .snapshot import MatrixRuntimeStateSnapshotMixin


class MatrixRuntimeState(
    MatrixRuntimeStateInitMixin,
    MatrixRuntimeStateMarksMixin,
    MatrixRuntimeStateSnapshotMixin,
):
    """Tracks runtime health for one Matrix adapter instance."""

    pass


# Preserve direct method attributes expected by consumers.
for _mixin in (
    MatrixRuntimeStateInitMixin,
    MatrixRuntimeStateMarksMixin,
    MatrixRuntimeStateSnapshotMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if _method_name.startswith("__"):
            continue
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixRuntimeState, _method_name, _method)


__all__ = ["MatrixRuntimeState"]
