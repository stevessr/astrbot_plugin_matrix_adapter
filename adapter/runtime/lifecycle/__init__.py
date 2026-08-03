"""Composable Matrix adapter runtime lifecycle helpers."""

import asyncio

from astrbot.api import logger

from ....storage.paths import MatrixStoragePaths
from .shutdown import MatrixAdapterRuntimeShutdownMixin
from .startup import MatrixAdapterRuntimeStartupMixin


class MatrixAdapterRuntimeLifecycleMixin(
    MatrixAdapterRuntimeStartupMixin,
    MatrixAdapterRuntimeShutdownMixin,
):
    """Start and terminate the Matrix adapter runtime."""

    pass


# Preserve direct method attributes exposed by the former lifecycle mixin.
for _mixin in (MatrixAdapterRuntimeStartupMixin, MatrixAdapterRuntimeShutdownMixin):
    for _method_name, _method in _mixin.__dict__.items():
        if callable(_method) and not _method_name.startswith("__"):
            setattr(MatrixAdapterRuntimeLifecycleMixin, _method_name, _method)


__all__ = [
    "MatrixAdapterRuntimeLifecycleMixin",
    "MatrixAdapterRuntimeShutdownMixin",
    "MatrixAdapterRuntimeStartupMixin",
    "MatrixStoragePaths",
    "asyncio",
    "logger",
]
