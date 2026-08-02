"""Layered Matrix client foundation."""

from .errors import MatrixAPIError
from .http import MatrixClientBase

__all__ = ["MatrixAPIError", "MatrixClientBase"]
