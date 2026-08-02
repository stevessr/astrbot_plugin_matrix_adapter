"""Layered Matrix adapter runtime lifecycle helpers."""

from .lifecycle import MatrixAdapterRuntimeLifecycleMixin
from .media_cache import MatrixAdapterRuntimeMediaCacheMixin
from .status import MatrixAdapterRuntimeStatusMixin


class MatrixAdapterRuntimeMixin(
    MatrixAdapterRuntimeStatusMixin,
    MatrixAdapterRuntimeMediaCacheMixin,
    MatrixAdapterRuntimeLifecycleMixin,
):
    """Compose adapter status, media-cache, and lifecycle behavior."""

    pass


__all__ = [
    "MatrixAdapterRuntimeLifecycleMixin",
    "MatrixAdapterRuntimeMediaCacheMixin",
    "MatrixAdapterRuntimeMixin",
    "MatrixAdapterRuntimeStatusMixin",
]
