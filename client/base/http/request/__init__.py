"""Composable Matrix HTTP request functionality."""

from typing import Any

import aiohttp

from astrbot.api import logger

from .....constants import ERROR_TRUNCATE_LENGTH_200, HTTP_ERROR_STATUS_400
from ...errors import MatrixAPIError
from .headers import MatrixHTTPHeadersMixin
from .transport import MatrixHTTPTransportMixin


class MatrixHTTPRequestMixin(MatrixHTTPHeadersMixin, MatrixHTTPTransportMixin):
    """Issue Matrix API requests and normalize failures."""

    pass


for _mixin in (MatrixHTTPHeadersMixin, MatrixHTTPTransportMixin):
    for _method_name, _method in _mixin.__dict__.items():
        if callable(_method) and not _method_name.startswith("__"):
            setattr(MatrixHTTPRequestMixin, _method_name, _method)


__all__ = [
    "Any",
    "ERROR_TRUNCATE_LENGTH_200",
    "HTTP_ERROR_STATUS_400",
    "MatrixAPIError",
    "MatrixHTTPRequestMixin",
    "aiohttp",
    "logger",
]
