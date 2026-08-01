"""Composable Matrix configuration implementation."""

from .core import MatrixConfigCoreMixin
from .device import MatrixConfigDeviceMixin
from .properties import MatrixConfigPropertiesMixin
from .validation import MatrixConfigValidationMixin


class MatrixConfig(
    MatrixConfigCoreMixin,
    MatrixConfigDeviceMixin,
    MatrixConfigPropertiesMixin,
    MatrixConfigValidationMixin,
):
    """Combined Matrix configuration API."""

    pass


__all__ = ["MatrixConfig"]
