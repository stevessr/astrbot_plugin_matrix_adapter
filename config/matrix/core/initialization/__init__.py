"""Matrix authentication, sync, and feature configuration state.

Public symbols re-exported for backward compatibility.
"""

from .core import MatrixConfigCoreInitializationMixin
from .e2ee import MatrixConfigE2eeInitializationMixin
from .features import MatrixConfigFeaturesInitializationMixin
from .identity import MatrixConfigIdentityInitializationMixin


class MatrixConfigCoreOperationsMixin(
    MatrixConfigCoreInitializationMixin,
    MatrixConfigIdentityInitializationMixin,
    MatrixConfigFeaturesInitializationMixin,
    MatrixConfigE2eeInitializationMixin,
):
    """Initialize the main Matrix configuration state."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixConfigCoreInitializationMixin,
    MatrixConfigIdentityInitializationMixin,
    MatrixConfigFeaturesInitializationMixin,
    MatrixConfigE2eeInitializationMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixConfigCoreOperationsMixin, _method_name, _method)


__all__ = [
    "MatrixConfigCoreInitializationMixin",
    "MatrixConfigCoreOperationsMixin",
    "MatrixConfigE2eeInitializationMixin",
    "MatrixConfigFeaturesInitializationMixin",
    "MatrixConfigIdentityInitializationMixin",
]
