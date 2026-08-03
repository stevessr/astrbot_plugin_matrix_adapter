"""Composable Matrix configuration core operations."""

from astrbot.api import logger

from ....constants import DEFAULT_TIMEOUT_MS_30000
from ....storage.stores.device import MatrixDeviceManager
from ....utils import parse_bool
from .initialization import MatrixConfigCoreOperationsMixin


class MatrixConfigCoreMixin(MatrixConfigCoreOperationsMixin):
    """Initialize the main Matrix configuration state."""

    pass


# Preserve direct attributes exposed by the former mixin.
MatrixConfigCoreMixin._parse_bool = MatrixConfigCoreOperationsMixin.__dict__[
    "_parse_bool"
]
for _method_name in ("_parse_int", "__init__"):
    setattr(
        MatrixConfigCoreMixin,
        _method_name,
        MatrixConfigCoreOperationsMixin.__dict__[_method_name],
    )


__all__ = [
    "DEFAULT_TIMEOUT_MS_30000",
    "MatrixConfigCoreMixin",
    "MatrixConfigCoreOperationsMixin",
    "MatrixDeviceManager",
    "logger",
    "parse_bool",
]
